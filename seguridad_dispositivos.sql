-- ============================================================
-- 16. DISPOSITIVO AUTORIZADO Y ALERTAS DE SEGURIDAD
-- ============================================================

-- Un dispositivo autorizado por empleado. Se registra solo la
-- primera vez que ficha desde un teléfono nuevo; si después intenta
-- fichar desde otro dispositivo, queda bloqueado hasta que el
-- gerente lo autorice desde el panel.
create table dispositivos_autorizados (
  id uuid primary key default gen_random_uuid(),
  empleado_id uuid not null references empleados(id) on delete cascade,
  device_id text not null,
  descripcion text, -- info del navegador/SO, solo para identificarlo en el panel
  fecha_autorizacion timestamptz not null default now(),
  unique (empleado_id)
);

-- Intentos de fichaje rechazados por dispositivo no autorizado,
-- para que el gerente los vea en la Central de alertas.
create table intentos_sospechosos (
  id uuid primary key default gen_random_uuid(),
  empleado_id uuid references empleados(id),
  tipo text not null check (tipo in ('dispositivo_no_autorizado', 'dispositivo_compartido')),
  device_id text,
  creado_en timestamptz not null default now(),
  revisado boolean not null default false
);

alter table dispositivos_autorizados enable row level security;
alter table intentos_sospechosos enable row level security;

create policy "authenticated_full_access" on dispositivos_autorizados
  for all to authenticated using (true) with check (true);
create policy "authenticated_full_access" on intentos_sospechosos
  for all to authenticated using (true) with check (true);
-- anon no tiene ninguna política aquí: solo se tocan vía funciones seguras.

-- Columna en turnos_carga para poder detectar "dos empleados fichando
-- desde el mismo teléfono casi al mismo tiempo" (capa 4).
alter table turnos_carga add column if not exists device_id text;

-- ------------------------------------------------------------
-- verificar_pin actualizada: ahora también recibe el device_id
-- del teléfono y valida contra el dispositivo autorizado.
-- ------------------------------------------------------------
create or replace function verificar_pin(p_empleado_id uuid, p_pin text, p_device_id text default null)
returns table (
  id uuid,
  nombre text,
  rol text,
  modo_transporte text,
  resultado text -- 'ok' | 'incorrecto' | 'bloqueado' | 'dispositivo_no_autorizado'
)
language plpgsql
security definer
as $$
declare
  v_empleado record;
  v_dispositivo record;
  v_max_intentos int := 5;
  v_minutos_bloqueo int := 10;
begin
  select * into v_empleado from empleados
    where empleados.id = p_empleado_id and activo = true;

  if v_empleado is null then
    return query select null::uuid, null::text, null::text, null::text, 'incorrecto'::text;
    return;
  end if;

  if v_empleado.bloqueado_hasta is not null and v_empleado.bloqueado_hasta > now() then
    return query select v_empleado.id, v_empleado.nombre, null::text, null::text, 'bloqueado'::text;
    return;
  end if;

  if crypt(p_pin, v_empleado.pin_hash) <> v_empleado.pin_hash then
    -- PIN incorrecto: incrementa intentos y bloquea si supera el máximo
    update empleados
      set intentos_fallidos = intentos_fallidos + 1,
          bloqueado_hasta = case
            when intentos_fallidos + 1 >= v_max_intentos
            then now() + (v_minutos_bloqueo || ' minutes')::interval
            else bloqueado_hasta
          end
      where empleados.id = v_empleado.id;

    return query select v_empleado.id, v_empleado.nombre, null::text, null::text, 'incorrecto'::text;
    return;
  end if;

  -- PIN correcto: ahora valida el dispositivo (solo si se envió un device_id)
  if p_device_id is not null then
    select * into v_dispositivo from dispositivos_autorizados where empleado_id = v_empleado.id;

    if v_dispositivo is null then
      -- Primera vez que ficha: este dispositivo queda autorizado automáticamente.
      insert into dispositivos_autorizados (empleado_id, device_id) values (v_empleado.id, p_device_id);
    elsif v_dispositivo.device_id <> p_device_id then
      -- Dispositivo distinto al autorizado: se bloquea y se avisa al gerente.
      insert into intentos_sospechosos (empleado_id, tipo, device_id)
        values (v_empleado.id, 'dispositivo_no_autorizado', p_device_id);

      return query select v_empleado.id, v_empleado.nombre, null::text, null::text, 'dispositivo_no_autorizado'::text;
      return;
    end if;
  end if;

  update empleados set intentos_fallidos = 0, bloqueado_hasta = null
    where empleados.id = v_empleado.id;

  return query
  select v_empleado.id, v_empleado.nombre, v_empleado.rol,
         v_empleado.modo_transporte, 'ok'::text;
end;
$$;

-- ------------------------------------------------------------
-- El gerente usa esto desde el panel para autorizar un teléfono
-- nuevo (ej. el empleado cambió de móvil).
-- ------------------------------------------------------------
create or replace function resetear_dispositivo_empleado(p_empleado_id uuid)
returns void
language sql
security definer
as $$
  delete from dispositivos_autorizados where empleado_id = p_empleado_id;
$$;

comment on function resetear_dispositivo_empleado is
  'Borra el dispositivo autorizado de un empleado; el siguiente login desde cualquier teléfono queda autorizado como el nuevo.';
