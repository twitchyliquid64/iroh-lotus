# Running lotusd in Kubernetes

Images are published to `ghcr.io/twitchyliquid64/iroh-lotus` for `linux/amd64` and
`linux/arm64`, tagged with the release version (`0.0.4`) and `latest`. The binaries are
static, so the image is `distroless/static` and carries no shell or package manager;
`lotusd`, `lotusctl` and `lotusweb` are all on `PATH`, and `LOTUS_STATE_DIR` is preset to
`/var/lib/lotus` so `kubectl exec … lotusctl status` finds the control socket without
being told where it is.

```sh
docker run --rm -v lotus:/var/lib/lotus ghcr.io/twitchyliquid64/iroh-lotus:latest
```

## What the deployment has to respect

A node's identity — its signing key, its endpoint id, and the `cluster-nodes` entry the
ledger holds for it — lives in the state directory. Three consequences shape everything
below:

- **One replica per state directory, and never clone the volume.** Two daemons over
  copies of one state dir are two nodes claiming one endpoint id. `addr_publish`
  deliberately declines to capture an entry listed under another endpoint, so the copy
  does not take over so much as sit there unlisted.
- **The volume is the node.** Lose it and the node is gone from the cluster; its
  `cluster-nodes` entry stays behind, and rejoining means a fresh invite. Back it up, or
  accept re-joining as the recovery path.
- **Joining happens once, out of band.** `lotusd bootstrap` refuses a state directory
  that already holds a cluster (`AlreadyInitialized`), so it cannot be an init container
  that runs on every start — the second start would fail and the pod would crash-loop.
  Its `--force` is *destructive*: it replaces the cluster that is already there, which in
  an init container means discarding the node's identity on every restart. Bootstrap with
  the one-shot Job below instead.

## 1. Namespace, volume, and the invite

Mint the invite on a node already in the cluster with `lotusctl invite`. It is a
credential and it redeems once.

```sh
kubectl create namespace lotus
kubectl -n lotus create secret generic lotus-invite --from-literal=invite='lotus1…'
```

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: lotus-state
  namespace: lotus
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 5Gi
```

## 2. Join the cluster, once

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: lotus-bootstrap
  namespace: lotus
spec:
  backoffLimit: 2
  template:
    spec:
      restartPolicy: Never
      securityContext:
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
      containers:
        - name: bootstrap
          image: ghcr.io/twitchyliquid64/iroh-lotus:latest
          # The invite is an argument, so it would otherwise be visible in the pod
          # spec to anyone who can read it; $(…) is Kubernetes' own env substitution,
          # not a shell — the image has no shell to expand it.
          args: ["lotusd", "bootstrap", "$(LOTUS_INVITE)"]
          env:
            - name: LOTUS_INVITE
              valueFrom:
                secretKeyRef:
                  name: lotus-invite
                  key: invite
          volumeMounts:
            - name: state
              mountPath: /var/lib/lotus
      volumes:
        - name: state
          persistentVolumeClaim:
            claimName: lotus-state
```

Wait for it, and delete the Secret once it has been redeemed:

```sh
kubectl -n lotus wait --for=condition=complete job/lotus-bootstrap --timeout=120s
kubectl -n lotus delete secret lotus-invite
```

## 3. Run the daemon

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: lotusd
  namespace: lotus
spec:
  replicas: 1
  serviceName: lotusd
  selector:
    matchLabels:
      app: lotusd
  template:
    metadata:
      labels:
        app: lotusd
    spec:
      securityContext:
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
      containers:
        - name: lotusd
          image: ghcr.io/twitchyliquid64/iroh-lotus:latest
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
          # `lotusctl status` answers over the control socket, so it succeeds only
          # once the daemon is actually serving — not merely running.
          readinessProbe:
            exec:
              command: ["lotusctl", "status"]
            periodSeconds: 10
          livenessProbe:
            exec:
              command: ["lotusctl", "status"]
            periodSeconds: 30
            failureThreshold: 3
          volumeMounts:
            - name: state
              mountPath: /var/lib/lotus

        # Optional. lotusweb binds 127.0.0.1:8080 by default, which nothing outside
        # the pod can reach, so it is told to bind the pod's own address. It shares
        # the daemon's state dir because that is where the control socket is, and it
        # can write to the ledger — put an authenticating proxy in front of it, or
        # leave it out and use `kubectl exec … lotusctl`.
        - name: lotusweb
          image: ghcr.io/twitchyliquid64/iroh-lotus:latest
          args: ["lotusweb", "--listen", "0.0.0.0:8080"]
          ports:
            - name: http
              containerPort: 8080
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
          volumeMounts:
            - name: state
              mountPath: /var/lib/lotus

      volumes:
        - name: state
          persistentVolumeClaim:
            claimName: lotus-state
```

```yaml
apiVersion: v1
kind: Service
metadata:
  name: lotusd
  namespace: lotus
spec:
  selector:
    app: lotusd
  ports:
    - name: http
      port: 8080
      targetPort: http
```

Confirm the node is talking to the cluster — peers `connected`, and a head that moves:

```sh
kubectl -n lotus exec statefulset/lotusd -c lotusd -- lotusctl status
```

## Networking

The daemon dials out; nothing needs to reach it on a fixed port, so no `hostPort` or
inbound rule is required. It picks an ephemeral UDP port and reaches peers through iroh's
hole-punching, falling back to the n0 relays (`--relay none` turns that off and leaves
direct connections only, which on pod networking usually means a node that only talks to
peers it can route to directly).

Pod addresses are the one wrinkle: a pod's IP is not reachable from outside the cluster,
and it changes on every reschedule. `addr_publish` republishes the node's address as it
moves, so the ledger keeps up on its own, and the relay carries the traffic meanwhile.
Where peers share a LAN with the node and you would rather they connect directly,
`hostNetwork: true` puts the daemon on the node's own addresses — at the cost of the pod
seeing the host's whole network namespace.
