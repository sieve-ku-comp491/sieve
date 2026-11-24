-- The state of each finding, and the reasons an export is refused, as in
-- docs/finding-states.md, "How the state is worked out".

create view finding_states as
select
  f.id as finding_id,
  f.scan_id,
  f.group_id,
  case
    when exists (
      select 1 from report_findings rf join reports r on r.id = rf.report_id
      where rf.finding_id = f.id and r.status = 'exported'
    ) then 'reported'
    when le.id is not null and (cr.id is null or cr.finding_edit_id is distinct from le.id) then 'edited'
    when cr.decision = 'reject' then 'rejected'
    when cr.decision = 'approve' then 'approved'
    when v.id is not null then 'triaged'
    when exists (
      select 1 from triage_runs t where t.scan_id = f.scan_id and t.grouped_at is not null
    ) then 'grouped'
    else 'new'
  end as state,
  cr.id as counting_review_id,
  (own.id is null and cr.id is not null) as carried
from findings f
left join lateral (
  select r.* from reviews r where r.finding_id = f.id order by r.created_at desc limit 1
) own on true
left join lateral (
  select r.* from reviews r where f.hidden and r.id = f.carried_review_id
) car on true
left join lateral (
  select coalesce(own.id, car.id) as id,
         coalesce(own.decision, car.decision) as decision,
         case when own.id is not null then own.finding_edit_id else car.finding_edit_id end as finding_edit_id
) cr on true
left join lateral (
  select e.id from finding_edits e where e.finding_id = f.id order by e.created_at desc limit 1
) le on true
left join lateral (
  select v.id from verdicts v
  where v.finding_id = f.id or (f.group_id is not null and v.group_id = f.group_id)
  order by v.created_at desc limit 1
) v on true;

create function export_refusals(p_report uuid) returns table (reason text) language sql stable as $$
  with r as (select * from reports where id = p_report),
  latest_text as (
    select t.* from report_texts t join r on t.report_id = r.id order by t.version desc limit 1
  ),
  members as (
    select s.finding_id, s.state from finding_states s, r
    where (r.finding_id is not null and s.finding_id = r.finding_id)
       or (r.group_id is not null and s.group_id = r.group_id)
  )
  select 'report is already exported' from r where r.status = 'exported'
  union all
  select 'report has no text' where not exists (select 1 from latest_text)
  union all
  select 'current report text is not approved' from latest_text where approved_at is null
  union all
  select 'finding ' || finding_id || ' is ' || state || ', not decided'
    from members where state in ('new', 'grouped', 'triaged', 'edited')
  union all
  select 'no approved finding in the report'
    where not exists (select 1 from members where state = 'approved')
$$;
