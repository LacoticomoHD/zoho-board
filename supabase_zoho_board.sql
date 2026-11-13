-- Zoho-Board: eigenes Schema "zoho_board", komplett getrennt von den Don-Döner-Tabellen.
-- Kein direkter Tabellenzugriff von außen; alles läuft über die zb_*-Funktionen mit Team-Code (nur der SHA-256-Hash liegt in der DB).
create schema if not exists zoho_board;
revoke all on schema zoho_board from public, anon, authenticated;

create table zoho_board.settings (id int primary key default 1 check (id=1), code_hash text not null);
insert into zoho_board.settings(code_hash) values ('<HASH DES TEAM-CODES, nicht im Repo>');

create table zoho_board.tickets (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  author text not null check (length(trim(author)) between 2 and 80),
  kind text not null check (kind in ('Fehler','Problem','Verbesserung')),
  area text not null check (length(area) <= 60),
  priority text not null check (priority in ('hoch','mittel','niedrig')),
  title text not null check (length(trim(title)) between 3 and 160),
  description text not null default '' check (length(description) <= 8000),
  status text not null default 'aufgenommen' check (status in ('aufgenommen','abgestimmt','gesendet','geloest','verworfen')),
  status_log jsonb not null default '[]'::jsonb
);
create table zoho_board.comments (
  id bigserial primary key,
  ticket_id bigint not null references zoho_board.tickets(id) on delete cascade,
  created_at timestamptz not null default now(),
  author text not null check (length(trim(author)) between 2 and 80),
  body text not null check (length(trim(body)) between 1 and 4000)
);
create table zoho_board.shots (
  id bigserial primary key,
  ticket_id bigint not null references zoho_board.tickets(id) on delete cascade,
  created_at timestamptz not null default now(),
  author text not null,
  data text not null check (data like 'data:image/%' and length(data) <= 2500000)
);
create index on zoho_board.comments(ticket_id);
create index on zoho_board.shots(ticket_id);
alter table zoho_board.settings enable row level security;
alter table zoho_board.tickets enable row level security;
alter table zoho_board.comments enable row level security;
alter table zoho_board.shots enable row level security;

create or replace function zoho_board.ok(p_code text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if p_code is null or encode(extensions.digest(p_code,'sha256'),'hex') <> (select code_hash from zoho_board.settings where id=1) then
    raise exception 'Falscher Team-Code' using errcode = '28000';
  end if;
end $$;

create or replace function public.zb_list(p_code text) returns jsonb
language plpgsql security definer set search_path = '' as $$
begin
  perform zoho_board.ok(p_code);
  return coalesce((select jsonb_agg(jsonb_build_object(
    'id',t.id,'created_at',t.created_at,'updated_at',t.updated_at,'author',t.author,'kind',t.kind,'area',t.area,
    'priority',t.priority,'title',t.title,'description',t.description,'status',t.status,'status_log',t.status_log,
    'comments',coalesce((select jsonb_agg(jsonb_build_object('id',c.id,'author',c.author,'body',c.body,'created_at',c.created_at) order by c.created_at) from zoho_board.comments c where c.ticket_id=t.id),'[]'::jsonb),
    'shots',coalesce((select jsonb_agg(s.id order by s.id) from zoho_board.shots s where s.ticket_id=t.id),'[]'::jsonb)
  ) order by t.created_at desc) from zoho_board.tickets t),'[]'::jsonb);
end $$;

create or replace function public.zb_add_ticket(p_code text, p_author text, p_kind text, p_area text, p_priority text, p_title text, p_description text, p_shots text[] default '{}')
returns bigint language plpgsql security definer set search_path = '' as $$
declare v_id bigint; s text;
begin
  perform zoho_board.ok(p_code);
  if coalesce(array_length(p_shots,1),0) > 5 then raise exception 'Maximal 5 Screenshots'; end if;
  insert into zoho_board.tickets(author,kind,area,priority,title,description,status_log)
  values (trim(p_author),p_kind,coalesce(p_area,''),p_priority,trim(p_title),coalesce(p_description,''),
          jsonb_build_array(jsonb_build_object('s','aufgenommen','by',trim(p_author),'at',now())))
  returning id into v_id;
  foreach s in array coalesce(p_shots,'{}') loop
    insert into zoho_board.shots(ticket_id,author,data) values (v_id,trim(p_author),s);
  end loop;
  return v_id;
end $$;

create or replace function public.zb_add_shot(p_code text, p_ticket bigint, p_author text, p_data text)
returns bigint language plpgsql security definer set search_path = '' as $$
declare v_id bigint;
begin
  perform zoho_board.ok(p_code);
  if length(trim(coalesce(p_author,''))) < 2 then raise exception 'Name fehlt'; end if;
  if (select count(*) from zoho_board.shots where ticket_id=p_ticket) >= 8 then raise exception 'Maximal 8 Screenshots je Punkt'; end if;
  insert into zoho_board.shots(ticket_id,author,data) values (p_ticket,trim(p_author),p_data) returning id into v_id;
  update zoho_board.tickets set updated_at=now() where id=p_ticket;
  return v_id;
end $$;

create or replace function public.zb_comment(p_code text, p_ticket bigint, p_author text, p_body text)
returns bigint language plpgsql security definer set search_path = '' as $$
declare v_id bigint;
begin
  perform zoho_board.ok(p_code);
  insert into zoho_board.comments(ticket_id,author,body) values (p_ticket,trim(p_author),trim(p_body)) returning id into v_id;
  update zoho_board.tickets set updated_at=now() where id=p_ticket;
  return v_id;
end $$;

create or replace function public.zb_set_status(p_code text, p_ids bigint[], p_status text, p_by text)
returns int language plpgsql security definer set search_path = '' as $$
declare n int;
begin
  perform zoho_board.ok(p_code);
  if length(trim(coalesce(p_by,''))) < 2 then raise exception 'Name fehlt'; end if;
  update zoho_board.tickets set status=p_status, updated_at=now(),
    status_log = status_log || jsonb_build_array(jsonb_build_object('s',p_status,'by',trim(p_by),'at',now()))
  where id = any(p_ids) and status <> p_status;
  get diagnostics n = row_count;
  return n;
end $$;

create or replace function public.zb_shot(p_code text, p_id bigint) returns text
language plpgsql security definer set search_path = '' as $$
begin
  perform zoho_board.ok(p_code);
  return (select data from zoho_board.shots where id=p_id);
end $$;

revoke all on function zoho_board.ok(text) from public, anon, authenticated;
revoke all on function public.zb_list(text), public.zb_add_ticket(text,text,text,text,text,text,text,text[]), public.zb_add_shot(text,bigint,text,text), public.zb_comment(text,bigint,text,text), public.zb_set_status(text,bigint[],text,text), public.zb_shot(text,bigint) from public;
grant execute on function public.zb_list(text), public.zb_add_ticket(text,text,text,text,text,text,text,text[]), public.zb_add_shot(text,bigint,text,text), public.zb_comment(text,bigint,text,text), public.zb_set_status(text,bigint[],text,text), public.zb_shot(text,bigint) to anon, authenticated;
