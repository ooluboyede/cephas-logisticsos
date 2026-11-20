# CEPHAS ML and Feature Engineering Standard

**Status: design contract; model pipelines and production feature services are not yet implemented.**

## Core principles

- Data quality and lineage precede model training.
- Every feature has an owner, definition, type, unit, source, freshness expectation and tenant scope.
- Training and inference use consistent, versioned transformations.
- Point-in-time correctness is mandatory to prevent temporal leakage.
- Feature computation must be reproducible and deterministic where practical.
- Missing, stale, malformed and out-of-range values have explicit handling rules.
- Sensitive features require documented purpose, access controls and retention.
- Model evaluation is segmented by customer and operational context; cross-customer pooling is prohibited unless explicitly authorized and legally approved.

## Initial feature families

### Shipment
- elapsed time since accepted, dispatched and last scan
- scan-event count and inter-scan intervals
- planned-versus-observed milestone deltas
- origin/destination lane history within the same tenant
- service level and shipment priority
- customs status and exception indicators

### Fleet
- odometer and engine-hour deltas
- maintenance recency and fault-code counts
- utilisation and idle-time ratios
- fuel-use rates where reliable telemetry exists
- vehicle class and operating context

### Route and delivery
- route distance and estimated travel duration
- stop density and service-time estimates
- time-window slack
- historical lane variability within tenant scope
- traffic and weather observations with source timestamps

### Hub and warehouse
- inbound/outbound parcel rates
- queue length and dwell time
- processing capacity and utilisation
- backlog age distribution
- shift and facility operating calendar

## Leakage and correctness controls

- Features must only use information available at prediction time.
- Labels and post-outcome events must never enter pre-outcome feature windows.
- Train/test splits must respect time and tenant boundaries.
- Fit preprocessing only on training partitions.
- Validate schema, nullability, units, ranges and freshness before inference.
- Store feature definition versions and source lineage with each model version.

## Model lifecycle

1. Approved dataset and tenant scope.
2. Data quality and leakage checks.
3. Versioned feature computation.
4. Reproducible training run.
5. Evaluation against agreed baselines.
6. Model card and limitations.
7. Signed artifact publication.
8. Signature and integrity verification before loading.
9. Controlled deployment and monitoring.
10. Drift, degradation and rollback review.

## Initial ML use cases

The first use case is shipment delay risk and predictive ETA. It must begin with baseline heuristics and transparent evaluation before any claim of predictive superiority. Fleet, route, hub and customs models follow only after their data contracts and labels are validated.
