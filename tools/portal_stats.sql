-- Script to get portal usage stats

-- Active Members

select count(*) as "Active Non Tutorial Members" from ma_member_attribute where member_id not in (select member_id from ma_member_attribute where name = 'email_address' and value like '%gpolab.bbn.com') and name='username' and member_id not in (select member_id from ma_member_attribute where name = 'member_enabled' and value = 'n');

-- GPO IdP Members

select count(*) "Active Non Tutorial GPO IdP Members" from ma_member_attribute where name = 'eppn' and value like '%gpolab%' and member_id not in (select member_id from ma_member_attribute where name = 'member_enabled' and value = 'n') and member_id not in (select member_id from ma_member_attribute where name = 'email_address' and value like '%gpolab.bbn.com');

-- Non GPO IdP Members

select count(*) "Active Non Tutorial Non GPO IdP Members" from ma_member_attribute where name = 'eppn' and value not like '%gpolab%' and member_id not in (select member_id from ma_member_attribute where name = 'member_enabled' and value = 'n') and member_id not in (select member_id from ma_member_attribute where name = 'email_address' and value like '%gpolab.bbn.com');

-- Non GPO Idp, Non SAVI, Non NTUA, Non .br - so basically InCommon

select count(*) "Active InCommon Members" from ma_member_attribute where name = 'eppn' and value not like '%gpolab%' and member_id not in (select member_id from ma_member_attribute where name = 'member_enabled' and value = 'n') and member_id not in (select member_id from ma_member_attribute where name = 'email_address' and value like '%gpolab.bbn.com') and lower(value) not like '%ntua.gr' and lower(value) not like '%savitestbed.ca' and lower(value) not like '%.br';

-- International users

select count(*) as "Active International Members" from ma_member_attribute where member_id not in (select member_id from ma_member_attribute where name = 'email_address' and value like '%gpolab.bbn.com') and name='username' and member_id not in (select member_id from ma_member_attribute where name = 'member_enabled' and value = 'n') and member_id in (select member_id from ma_member_attribute where name = 'email_address' and lower(value) not like '%.com' and lower(value) not like '%.edu' and lower(value) not like '%.mil' and lower(value) not like '%.gov' and lower(value) not like '%.org' and lower(value) not like '%.net');

-- Most popular institutions (using EPPN)

select trim(leading '@' from substring(lower(value) from '@.*$')) as "Most common member institutions", count(*) as members from ma_member_attribute where name = 'eppn' group by "Most common member institutions" order by members desc limit 30;

-- Most popular institutions using email, non tutorial
select trim(leading '@' from substring(lower(value) from '@.*$')) as "Most common member institutions by email", count(*) as members from ma_member_attribute where name = 'email_address' and value not like '%gpolab.bbn.com' group by "Most common member institutions by email" order by members descq limit 100;

-- Most popular countries / top level domains
select distinct substring(lower(value) from '%.#"_+#"' for '#') as "Most common TLDs", count(*) as members from ma_member_attribute where name = 'email_address' group by substring(lower(value) from '%.#"_+#"' for '#') order by members desc limit 25;

-- Active users in the last 4 months
select count(distinct member_id) as "Active users in last 4 months" from last_seen where ts > now() - interval '4 months';

select count(*) as "New Portal users in last 4 months" from logging_entry where message like 'Activated GENI user%' and event_time > now() - interval '4 months';

-- Source of new users in the last 4 months
select trim(leading '@' from substring(value from '@.*$')) as "Source of new members in last 4 months", count(*) as members from ma_member_attribute where name = 'eppn' and member_id in (select uuid(a.attribute_value) from logging_entry_attribute a, logging_entry l where l.id = a.event_id and l.message like 'Activated GENI user%' and l.event_time > now() - interval '4 months') group by "Source of new members in last 4 months" order by members desc limit 20;

-- Current Project Leads

select count(*) as "Project Leads" from ma_member_attribute where member_id not in (select member_id from ma_member_attribute where name = 'email_address' and value like '%gpolab.bbn.com') and name='PROJECT_LEAD' and member_id not in (select member_id from ma_member_attribute where name = 'member_enabled' and value = 'n');

select count(*) as "Current Projects" from pa_project where expired != 't';
select count(*) as "New Projects in last 4 months" from pa_project where expired != 't' and creation > now() - interval '4 months';
select count(*) as "Projects with Slices" from pa_project where expired != 't' and project_id in (select project_id from sa_slice where expired != 't');
select count(*) as "Current Slices" from sa_slice where expired != 't';
select count(*) as "New Slices in last 4 months" from sa_slice where creation > now() - interval '4 months';
select count(*) as "Portal Resource Reservations in last 4 months" from logging_entry where message like 'Add resource request%' and event_time > now() - interval '4 months';

-- Stats on current slivers

-- Monitoring slices that should really be ignored (with sliver count)
-- urn:publicid:IDN+ch.geni.net:gpoamcanary+slice+sitemon                               |    53
-- urn:publicid:IDN+ch.geni.net:gpo-infra+slice+gpoI15                                  |    31
-- urn:publicid:IDN+ch.geni.net:gpo-infra+slice+gpoI16                                  |    30
-- urn:publicid:IDN+ch.geni.net:gpo-infra+slice+GeniSiteMon                             |    24
-- urn:publicid:IDN+ch.geni.net:SydTest+slice+ofCoreMonitor-syd                         |    11

select count(*) as "Current Portal Slivers" from sa_sliver_info where slice_urn not in ('urn:publicid:IDN+ch.geni.net:gpoamcanary+slice+sitemon', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+gpoI15', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+gpoI16', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+GeniSiteMon', 'urn:publicid:IDN+ch.geni.net:SydTest+slice+ofCoreMonitor-syd');

select count(distinct slice_urn) as "Slices with Resources" from sa_sliver_info  where slice_urn not in ('urn:publicid:IDN+ch.geni.net:gpoamcanary+slice+sitemon', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+gpoI15', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+gpoI16', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+GeniSiteMon', 'urn:publicid:IDN+ch.geni.net:SydTest+slice+ofCoreMonitor-syd');

select count(distinct slice_urn) as "Slices Reserving Resources in the last month" from sa_sliver_info where creation > now() - interval '1 month' and slice_urn not in ('urn:publicid:IDN+ch.geni.net:gpoamcanary+slice+sitemon', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+gpoI15', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+gpoI16', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+GeniSiteMon', 'urn:publicid:IDN+ch.geni.net:SydTest+slice+ofCoreMonitor-syd');

select count(distinct slice_urn) as "Slices using Stitching now" from sa_sliver_info where aggregate_urn like '%al2s%' or aggregate_urn like '%stitch%' or aggregate_urn like '%dragon.max%' and slice_urn not in ('urn:publicid:IDN+ch.geni.net:gpoamcanary+slice+sitemon', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+gpoI15', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+gpoI16', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+GeniSiteMon', 'urn:publicid:IDN+ch.geni.net:SydTest+slice+ofCoreMonitor-syd');

select slice_urn as "Most Active Current Slices", count(*) as slivers from sa_sliver_info where slice_urn not in ('urn:publicid:IDN+ch.geni.net:gpoamcanary+slice+sitemon', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+gpoI15', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+gpoI16', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+GeniSiteMon', 'urn:publicid:IDN+ch.geni.net:SydTest+slice+ofCoreMonitor-syd') group by slice_urn order by slivers desc limit 20;

select count(*) as "Aggregates" from service_registry where service_type = 0;

select count(distinct aggregate_urn) as "Aggregates with Reservations" from sa_sliver_info where slice_urn not in ('urn:publicid:IDN+ch.geni.net:gpoamcanary+slice+sitemon', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+gpoI15', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+gpoI16', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+GeniSiteMon', 'urn:publicid:IDN+ch.geni.net:SydTest+slice+ofCoreMonitor-syd');

select aggregate_urn as "Most Currently Used Aggregates", count(*) as slivers from sa_sliver_info where slice_urn not in ('urn:publicid:IDN+ch.geni.net:gpoamcanary+slice+sitemon', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+gpoI15', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+gpoI16', 'urn:publicid:IDN+ch.geni.net:gpo-infra+slice+GeniSiteMon', 'urn:publicid:IDN+ch.geni.net:SydTest+slice+ofCoreMonitor-syd') group by aggregate_urn order by slivers desc limit 20;

select p.project_name as "Most Active Projects in Last 4 months", count(distinct l.event_id) as "Reservations" from logging_entry_attribute l, pa_project p where l.attribute_name = 'PROJECT' and uuid(l.attribute_value) = p.project_id and l.event_id in (select id from logging_entry where message like 'Add resource request%' and event_time > now() - interval '4 months') group by "Most Active Projects in Last 4 months" order by "Reservations" desc limit 30;

select s.slice_urn as "Most Active Slices in Last 4 months", count(distinct l.event_id) as "Reservations" from logging_entry_attribute l, sa_slice s where l.attribute_name = 'SLICE' and uuid(l.attribute_value) = s.slice_id and l.event_id in (select id from logging_entry where message like 'Add resource request%' and event_time > now() - interval '4 months') group by "Most Active Slices in Last 4 months" order by "Reservations" desc limit 30;

select m.value as "Most Active Members in Last 4 months", count(distinct l.event_id) as "Reservations" from logging_entry_attribute l, ma_member_attribute m, logging_entry l2 where l2.id = l.event_id and m.name = 'email_address' and l2.user_id = m.member_id and l2.message like 'Add resource request%' and l2.event_time > now() - interval '4 months' group by "Most Active Members in Last 4 months" order by "Reservations" desc limit 30;
