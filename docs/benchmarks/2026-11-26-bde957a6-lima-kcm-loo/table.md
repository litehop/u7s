# KCM leave-one-out (Pss_Anon MiB, WordPress + MariaDB loaded, one install)

Baseline (untrimmed, median of the interleaved R runs): 41.28 MiB; baseline spread (noise floor): 1.16 MiB.

| controller excluded | KCM MiB | saved vs baseline |
|---|---|---|
| validatingadmissionpolicy-status-controller | 34.22 | 7.06 |
| garbage-collector-controller | 37.17 | 4.11 |
| endpointslice-mirroring-controller | 39.93 | 1.35 |
| daemonset-controller | 40.18 | 1.1 |
| certificatesigningrequest-signing-controller | 40.57 | 0.71 |
| disruption-controller | 40.69 | 0.59 |
| cronjob-controller | 40.72 | 0.56 |
| taint-eviction-controller | 40.80 | 0.48 |
| node-lifecycle-controller | 40.82 | 0.46 |
| ttl-after-finished-controller | 40.85 | 0.43 |
| resourcequota-controller | 40.90 | 0.38 |
| podgroup-protection-controller | 40.90 | 0.38 |
| token-cleaner-controller | 41.09 | 0.19 |
| storageversion-garbage-collector-controller | 41.12 | 0.16 |
| persistentvolume-binder-controller | 41.35 | -0.07 |
| ephemeral-volume-controller | 41.35 | -0.07 |
| storage-version-migrator-controller | 41.35 | -0.07 |
| statefulset-controller | 41.36 | -0.08 |
| endpoints-controller | 41.38 | -0.1 |
| resourceclaim-controller | 41.42 | -0.14 |
| volumeattributesclass-protection-controller | 41.42 | -0.14 |
| root-ca-certificate-publisher-controller | 41.43 | -0.15 |
| job-controller | 41.46 | -0.18 |
| device-taint-eviction-controller | 41.46 | -0.18 |
| endpointslice-controller | 41.63 | -0.35 |
| certificatesigningrequest-approving-controller | 41.63 | -0.35 |
| persistentvolume-attach-detach-controller | 41.63 | -0.35 |
| legacy-serviceaccount-token-cleaner-controller | 41.78 | -0.5 |
| persistentvolume-expander-controller | 41.80 | -0.52 |
| selinux-warning-controller | 41.80 | -0.52 |
| pod-garbage-collector-controller | 41.84 | -0.56 |
| node-ipam-controller | 41.85 | -0.57 |
| namespace-controller | 41.87 | -0.59 |
| ttl-controller | 41.87 | -0.59 |
| deployment-controller | 41.89 | -0.61 |
| horizontal-pod-autoscaler-controller | 41.91 | -0.63 |
| podcertificaterequest-cleaner-controller | 41.92 | -0.64 |
| persistentvolume-protection-controller | 41.95 | -0.67 |
| resourcepoolstatusrequest-controller | 41.96 | -0.68 |
| replicationcontroller-controller | 42.00 | -0.72 |
| certificatesigningrequest-cleaner-controller | 42.09 | -0.81 |
| bootstrap-signer-controller | 42.09 | -0.81 |
| persistentvolumeclaim-protection-controller | 42.11 | -0.83 |
| kube-apiserver-serving-clustertrustbundle-publisher-controller | 42.71 | -1.43 |
| serviceaccount-controller | 42.77 | -1.49 |
| replicaset-controller | 43.49 | -2.21 |
