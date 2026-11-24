create extension if not exists pgcrypto;

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  name text not null default '',
  email text,
  phone text,
  role text not null default 'reviewer' check (role in ('owner', 'editor', 'reviewer')),
  must_change_password boolean not null default false,
  created_at timestamptz not null default now()
);

create table public.patents (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  patent_number text not null default '',
  owner text not null default '',
  category text not null default '',
  status text not null default 'pending'
    check (status in ('active', 'in_review', 'pending', 'filed', 'granted', 'expiring', 'expired', 'rejected')),
  filing_date date,
  renewal_date date,
  estimated_value numeric(15, 2) not null default 0 check (estimated_value >= 0),
  description text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.products (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  category text not null default '',
  description text not null default '',
  sku text not null default '',
  price_cents bigint not null default 0 check (price_cents >= 0),
  stock_quantity bigint not null default 0 check (stock_quantity >= 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index products_sku_unique on public.products (upper(sku)) where sku <> '';
create index patents_updated on public.patents (updated_at desc);
create index patents_status on public.patents (status);
create index products_name on public.products (name);

create table public.product_patents (
  product_id uuid not null references public.products (id) on delete cascade,
  patent_id uuid not null references public.patents (id) on delete cascade,
  primary key (product_id, patent_id)
);

create table public.suppliers (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  service text not null default '',
  email text not null default '',
  phone text not null default '',
  status text not null default 'active' check (status in ('active', 'in_review', 'inactive')),
  notes text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index suppliers_name on public.suppliers (name);

create table public.collections (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text not null default '',
  is_public boolean not null default false,
  patent_ids uuid[] not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.sales (
  id uuid primary key default gen_random_uuid(),
  receipt_number text not null unique,
  cashier_id uuid not null references public.profiles (id),
  customer_name text not null default '',
  items jsonb not null,
  subtotal_cents bigint not null check (subtotal_cents >= 0),
  tax_cents bigint not null check (tax_cents >= 0),
  total_cents bigint not null check (total_cents >= 0),
  amount_received_cents bigint not null check (amount_received_cents >= 0),
  change_cents bigint not null check (change_cents >= 0),
  payment_method text not null check (payment_method in ('cash', 'card', 'other')),
  status text not null default 'completed' check (status in ('completed', 'refunded')),
  refunded_at timestamptz,
  refunded_by uuid references public.profiles (id),
  refund_reason text not null default '',
  created_at timestamptz not null default now()
);
create index sales_created on public.sales (created_at desc);

create table public.settings (
  setting_key text primary key,
  setting_value jsonb not null
);
insert into public.settings (setting_key, setting_value) values
  ('workspaceName', '"ANUCHO"'),
  ('currency', '"USD"'),
  ('timezone', '"UTC"'),
  ('taxRate', '0')
on conflict (setting_key) do nothing;

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, name, email, phone)
  values (
    new.id,
    coalesce(new.raw_user_meta_data ->> 'name', ''),
    new.email,
    new.phone
  );
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

create or replace function public.current_workspace_role()
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select case when must_change_password then null else role end
    from public.profiles where id = (select auth.uid())
$$;

create or replace function public.bootstrap_owner(owner_name text)
returns public.profiles
language plpgsql
security definer
set search_path = ''
as $$
declare
  result public.profiles;
begin
  if auth.uid() is null then
    raise exception 'Sign in before setting up the workspace.' using errcode = '42501';
  end if;

  perform pg_advisory_xact_lock(19012026);
  if exists (select 1 from public.profiles where role = 'owner') then
    raise exception 'This workspace already has an owner.' using errcode = '23505';
  end if;

  update public.profiles
    set name = nullif(trim(owner_name), ''), role = 'owner'
    where id = auth.uid()
    returning * into result;

  if result.id is null then
    raise exception 'The signed-in profile was not found.' using errcode = 'P0002';
  end if;
  return result;
end;
$$;

create or replace function public.complete_sale(
  sale_items jsonb,
  payment_method text,
  amount_received_cents bigint,
  customer_name text,
  receipt_number text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  item jsonb;
  product_row public.products;
  resolved_items jsonb := '[]'::jsonb;
  subtotal bigint := 0;
  tax_rate numeric := 0;
  tax bigint;
  total bigint;
  received bigint;
  result public.sales;
  item_count integer;
begin
  if auth.uid() is null or public.current_workspace_role() not in ('owner', 'editor') then
    raise exception 'You do not have permission to complete sales.' using errcode = '42501';
  end if;
  if jsonb_typeof(sale_items) <> 'array' or jsonb_array_length(sale_items) not between 1 and 100 then
    raise exception 'A sale must contain between 1 and 100 products.' using errcode = '22023';
  end if;
  if payment_method not in ('cash', 'card', 'other') then
    raise exception 'Choose cash, card, or other as the payment method.' using errcode = '22023';
  end if;
  select count(distinct value ->> 'productId') into item_count from jsonb_array_elements(sale_items);
  if item_count <> jsonb_array_length(sale_items) then
    raise exception 'Each product may only appear once in a sale.' using errcode = '22023';
  end if;

  for item in select value from jsonb_array_elements(sale_items)
  loop
    if coalesce((item ->> 'quantity')::bigint, 0) < 1 then
      raise exception 'Item quantity must be at least one.' using errcode = '22023';
    end if;
    select * into product_row
      from public.products
      where id = (item ->> 'productId')::uuid
      for update;
    if not found then
      raise exception 'A product in this sale is no longer available.' using errcode = 'P0002';
    end if;
    if product_row.stock_quantity < (item ->> 'quantity')::bigint then
      raise exception '% does not have enough stock for this sale.', product_row.name using errcode = '23514';
    end if;
    subtotal := subtotal + product_row.price_cents * (item ->> 'quantity')::bigint;
    resolved_items := resolved_items || jsonb_build_array(jsonb_build_object(
      'productId', product_row.id,
      'name', product_row.name,
      'sku', product_row.sku,
      'quantity', (item ->> 'quantity')::bigint,
      'unitPriceCents', product_row.price_cents,
      'lineTotalCents', product_row.price_cents * (item ->> 'quantity')::bigint
    ));
  end loop;

  select (setting_value #>> '{}')::numeric into tax_rate
    from public.settings where setting_key = 'taxRate';
  tax := round(subtotal * coalesce(tax_rate, 0) / 100);
  total := subtotal + tax;
  received := case when payment_method = 'cash' then amount_received_cents else total end;
  if received is null or received < total then
    raise exception 'The amount received must cover the sale total.' using errcode = '22023';
  end if;

  for item in select value from jsonb_array_elements(resolved_items)
  loop
    update public.products
      set stock_quantity = stock_quantity - (item ->> 'quantity')::bigint, updated_at = now()
      where id = (item ->> 'productId')::uuid;
  end loop;

  insert into public.sales (
    receipt_number, cashier_id, customer_name, items, subtotal_cents, tax_cents,
    total_cents, amount_received_cents, change_cents, payment_method
  ) values (
    receipt_number, auth.uid(), coalesce(customer_name, ''), resolved_items, subtotal, tax,
    total, received, received - total, payment_method
  ) returning * into result;

  return to_jsonb(result);
end;
$$;

create or replace function public.refund_sale(sale_id uuid, reason text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  sale_row public.sales;
  item jsonb;
begin
  if auth.uid() is null or public.current_workspace_role() not in ('owner', 'editor') then
    raise exception 'You do not have permission to refund sales.' using errcode = '42501';
  end if;
  select * into sale_row from public.sales where id = sale_id for update;
  if not found then
    raise exception 'Sale not found.' using errcode = 'P0002';
  end if;
  if sale_row.status <> 'completed' then
    raise exception 'This sale has already been refunded.' using errcode = '23514';
  end if;

  for item in select value from jsonb_array_elements(sale_row.items)
  loop
    update public.products
      set stock_quantity = stock_quantity + (item ->> 'quantity')::bigint, updated_at = now()
      where id = (item ->> 'productId')::uuid;
    if not found then
      raise exception 'Cannot restore stock because a product record no longer exists.' using errcode = '23503';
    end if;
  end loop;

  update public.sales
    set status = 'refunded', refunded_at = now(), refunded_by = auth.uid(), refund_reason = reason
    where id = sale_id
    returning * into sale_row;
  return to_jsonb(sale_row);
end;
$$;

alter table public.profiles enable row level security;
alter table public.patents enable row level security;
alter table public.products enable row level security;
alter table public.product_patents enable row level security;
alter table public.suppliers enable row level security;
alter table public.collections enable row level security;
alter table public.sales enable row level security;
alter table public.settings enable row level security;

create policy "Profiles are visible to signed-in workspace members"
  on public.profiles for select to authenticated
  using (id = (select auth.uid()) or public.current_workspace_role() = 'owner');
revoke update on public.profiles from anon, authenticated;

create policy "Workspace members can read patents" on public.patents
  for select to authenticated using (public.current_workspace_role() is not null);
create policy "Editors can manage patents" on public.patents
  for all to authenticated
  using (public.current_workspace_role() in ('owner', 'editor'))
  with check (public.current_workspace_role() in ('owner', 'editor'));

create policy "Workspace members can read products" on public.products
  for select to authenticated using (public.current_workspace_role() is not null);
create policy "Editors can manage products" on public.products
  for all to authenticated
  using (public.current_workspace_role() in ('owner', 'editor'))
  with check (public.current_workspace_role() in ('owner', 'editor'));

create policy "Workspace members can read product patent links" on public.product_patents
  for select to authenticated using (public.current_workspace_role() is not null);
create policy "Editors can manage product patent links" on public.product_patents
  for all to authenticated
  using (public.current_workspace_role() in ('owner', 'editor'))
  with check (public.current_workspace_role() in ('owner', 'editor'));

create policy "Workspace members can read suppliers" on public.suppliers
  for select to authenticated using (public.current_workspace_role() is not null);
create policy "Editors can manage suppliers" on public.suppliers
  for all to authenticated
  using (public.current_workspace_role() in ('owner', 'editor'))
  with check (public.current_workspace_role() in ('owner', 'editor'));

create policy "Workspace members can read collections" on public.collections
  for select to authenticated using (public.current_workspace_role() is not null);
create policy "Editors can manage collections" on public.collections
  for all to authenticated
  using (public.current_workspace_role() in ('owner', 'editor'))
  with check (public.current_workspace_role() in ('owner', 'editor'));

create policy "Workspace members can read sales" on public.sales
  for select to authenticated using (public.current_workspace_role() is not null);
create policy "Workspace members can read settings" on public.settings
  for select to authenticated using (public.current_workspace_role() is not null);
create policy "Owners can manage settings" on public.settings
  for all to authenticated
  using (public.current_workspace_role() = 'owner')
  with check (public.current_workspace_role() = 'owner');

grant select on public.profiles, public.patents, public.products, public.product_patents,
  public.suppliers, public.collections, public.sales, public.settings to authenticated;

grant execute on function public.bootstrap_owner(text) to authenticated;
grant execute on function public.complete_sale(jsonb, text, bigint, text, text) to authenticated;
grant execute on function public.refund_sale(uuid, text) to authenticated;

alter publication supabase_realtime add table public.patents;
alter publication supabase_realtime add table public.products;
alter publication supabase_realtime add table public.suppliers;
alter publication supabase_realtime add table public.collections;
alter publication supabase_realtime add table public.sales;
alter publication supabase_realtime add table public.settings;
alter publication supabase_realtime add table public.profiles;
