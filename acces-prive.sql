alter table public.profiles add column if not exists approved boolean not null default false;
alter table public.profiles add column if not exists attempts int not null default 0;
update public.profiles set approved = true where is_admin;

create table if not exists public.team_code (code text not null);
alter table public.team_code enable row level security;
revoke all on public.team_code from anon, authenticated;
insert into public.team_code(code) select 'odelicedesmeebrdmd2022' where not exists (select 1 from public.team_code);

create or replace function public.est_membre()
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((select approved or is_admin from profiles where id = auth.uid()), false)
$$;

create or replace function public.join_team(p_code text)
returns boolean language plpgsql security definer set search_path = public as $$
declare ok boolean; n int;
begin
  if auth.uid() is null then return false; end if;
  select attempts into n from profiles where id = auth.uid();
  if n is null or n >= 5 then return false; end if;
  select exists(select 1 from team_code where lower(trim(code)) = lower(trim(p_code))) into ok;
  if ok then
    update profiles set approved = true where id = auth.uid();
  else
    update profiles set attempts = attempts + 1 where id = auth.uid();
  end if;
  return ok;
end $$;

create or replace function public.get_team_code()
returns text language sql stable security definer set search_path = public as $$
  select case when est_admin() then (select code from team_code limit 1) end
$$;

create or replace function public.set_team_code(p_code text)
returns boolean language plpgsql security definer set search_path = public as $$
begin
  if not est_admin() or p_code is null or char_length(trim(p_code)) < 4 then return false; end if;
  update team_code set code = trim(p_code);
  return true;
end $$;

alter policy "profils lisibles" on public.profiles to authenticated
  using (id = auth.uid() or est_membre());
alter policy "creer son profil" on public.profiles to authenticated
  with check (id = auth.uid() and is_admin = false and approved = false and attempts = 0);
alter policy "taches lisibles" on public.tasks to authenticated using (est_membre());
alter policy "annonces lisibles" on public.announcements to authenticated using (est_membre());
alter policy "manques lisibles" on public.manques to authenticated using (est_membre());
alter policy "ajout manque" on public.manques to authenticated
  with check (added_by = auth.uid() and est_membre());

create or replace function public.toggle_task(task_id bigint, new_done boolean)
returns void language plpgsql security definer set search_path = public as $$
declare n text;
begin
  if not est_membre() then return; end if;
  select name into n from profiles where id = auth.uid();
  update tasks set
    done = new_done,
    done_by = case when new_done then auth.uid() else null end,
    done_by_name = case when new_done then n else null end,
    done_at = case when new_done then now() else null end
  where id = task_id;
end $$;

create or replace function public.resolve_manque(p_id bigint)
returns void language sql security definer set search_path = public as $$
  update public.manques m
  set resolved = true, resolved_at = now(),
      resolved_by_name = (select name from public.profiles where id = auth.uid())
  where m.id = p_id and not m.resolved and public.est_membre();
$$;

revoke all on function public.toggle_task(bigint, boolean) from public, anon;
revoke all on function public.resolve_manque(bigint) from public, anon;
revoke all on function public.ping() from public, anon;
revoke all on function public.join_team(text) from public, anon;
revoke all on function public.get_team_code() from public, anon;
revoke all on function public.set_team_code(text) from public, anon;
revoke all on function public.est_membre() from public, anon;
revoke all on function public.est_admin() from public, anon;
grant execute on function public.toggle_task(bigint, boolean), public.resolve_manque(bigint), public.ping(), public.join_team(text), public.get_team_code(), public.set_team_code(text), public.est_membre(), public.est_admin() to authenticated;
