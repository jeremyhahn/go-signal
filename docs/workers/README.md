# Workers

Background workers that run on a schedule or continuously, porting Java Signal-Server's Dropwizard commands to Go.

Populated in Phase 1.4 of the port plan.

| Document                              | Covers                                                       |
|---------------------------------------|--------------------------------------------------------------|
| [catalog.md](catalog.md) *(Phase 1.4)* | Complete list of workers: name, schedule, inputs, outputs.  |
| [scheduling.md](scheduling.md) *(Phase 1.4)* | In-process cron + leader-election model for multi-instance deployments. |
