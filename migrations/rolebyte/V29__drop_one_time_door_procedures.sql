-- V29: the register's one-time door is gone from its service, and two procedures
-- were called only by it, so both are dropped:
--   * `rolebyte.bootstrap_state` answered whether any tenant administrator exists
--     and took an advisory lock while the door made the first company;
--   * `rolebyte.own_rung_register` put the register's own service and its
--     administrator rung on the deployment's list.
-- The register now lists itself with its levels at its own start, through the
-- declaration procedures. No data is touched: what `own_rung_register` wrote
-- earlier in an existing database stays as it is.
--
-- The advisory lock key `hashtext('rolebyte.bootstrap')` stays. `deployment_admin_apply`
-- is its only taker and keeps it, so that two concurrent calls cannot both make a
-- first company.
DROP PROCEDURE IF EXISTS rolebyte.bootstrap_state(jsonb, jsonb);
DROP PROCEDURE IF EXISTS rolebyte.own_rung_register(jsonb, jsonb);
