const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    }
  });

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method;

      // Libera chamadas do navegador
      if (method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type"
          }
        });
      }

      // TESTE
      if (path === "/api/health" && method === "GET") {
        return json({
          ok: true,
          sistema: "Emirates Parque Flamboyant",
          banco: "D1 conectado"
        });
      }

      // =========================
      // COLABORADORES
      // =========================

      if (path === "/api/employees" && method === "GET") {
        const result = await env.DB.prepare(`
          SELECT *
          FROM employees
          ORDER BY name COLLATE NOCASE
        `).all();

        return json(result.results || []);
      }

      if (path === "/api/employees" && method === "POST") {
        const body = await request.json();

        if (!body.name || !body.name.trim()) {
          return json({ error: "Nome é obrigatório." }, 400);
        }

        const result = await env.DB.prepare(`
          INSERT INTO employees
          (name, role, registration, team, company, status)
          VALUES (?, ?, ?, ?, ?, ?)
        `).bind(
          body.name.trim(),
          body.role || "",
          body.registration || "",
          body.team || "",
          body.company || "TERRAL INCORPORADORA",
          body.status || "ATIVO"
        ).run();

        return json({
          ok: true,
          id: result.meta.last_row_id
        }, 201);
      }

      // =========================
      // SERVIÇOS / TAREFAS
      // =========================

      if (path === "/api/tasks" && method === "GET") {
        const result = await env.DB.prepare(`
          SELECT *
          FROM tasks
          WHERE active = 1
          ORDER BY description COLLATE NOCASE
        `).all();

        return json(result.results || []);
      }

      if (path === "/api/tasks" && method === "POST") {
        const body = await request.json();

        if (!body.description || !body.unit) {
          return json({
            error: "Descrição e unidade são obrigatórias."
          }, 400);
        }

        const result = await env.DB.prepare(`
          INSERT INTO tasks
          (description, unit, unit_value, active)
          VALUES (?, ?, ?, ?)
        `).bind(
          body.description.trim(),
          body.unit.trim(),
          Number(body.unit_value || 0),
          body.active === false ? 0 : 1
        ).run();

        return json({
          ok: true,
          id: result.meta.last_row_id
        }, 201);
      }

      // =========================
      // PONTO
      // =========================

      if (path === "/api/time-entries" && method === "GET") {
        const result = await env.DB.prepare(`
          SELECT
            t.*,
            e.name AS employee_name,
            e.role AS employee_role
          FROM time_entries t
          JOIN employees e ON e.id = t.employee_id
          ORDER BY t.work_date DESC, e.name COLLATE NOCASE
        `).all();

        return json(result.results || []);
      }

      if (path === "/api/time-entries" && method === "POST") {
        const body = await request.json();

        if (!body.employee_id || !body.work_date) {
          return json({
            error: "Colaborador e data são obrigatórios."
          }, 400);
        }

        const result = await env.DB.prepare(`
          INSERT INTO time_entries (
            employee_id,
            work_date,
            entry_time,
            break_start,
            break_end,
            exit_time,
            normal_hours,
            overtime_hours,
            occurrence,
            notes,
            launched_by
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          Number(body.employee_id),
          body.work_date,
          body.entry_time || "",
          body.break_start || "",
          body.break_end || "",
          body.exit_time || "",
          Number(body.normal_hours || 0),
          Number(body.overtime_hours || 0),
          body.occurrence || "",
          body.notes || "",
          body.launched_by || ""
        ).run();

        return json({
          ok: true,
          id: result.meta.last_row_id
        }, 201);
      }

      // =========================
      // PRODUÇÃO
      // =========================

      if (path === "/api/production" && method === "GET") {
        const result = await env.DB.prepare(`
          SELECT
            p.*,
            e.name AS employee_name,
            t.description AS task_description,
            t.unit AS task_unit
          FROM production_entries p
          JOIN employees e ON e.id = p.employee_id
          JOIN tasks t ON t.id = p.task_id
          ORDER BY p.work_date DESC, e.name COLLATE NOCASE
        `).all();

        return json(result.results || []);
      }

      if (path === "/api/production" && method === "POST") {
        const body = await request.json();

        if (!body.employee_id || !body.task_id || !body.work_date) {
          return json({
            error: "Colaborador, serviço e data são obrigatórios."
          }, 400);
        }

        const quantity = Number(body.quantity || 0);
        const unitValue = Number(body.unit_value || 0);
        const totalValue = quantity * unitValue;

        const result = await env.DB.prepare(`
          INSERT INTO production_entries (
            employee_id,
            task_id,
            work_date,
            tower,
            floor,
            location,
            details,
            quantity,
            unit_value,
            total_value,
            launched_by
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          Number(body.employee_id),
          Number(body.task_id),
          body.work_date,
          body.tower || "",
          body.floor || "",
          body.location || "",
          body.details || "",
          quantity,
          unitValue,
          totalValue,
          body.launched_by || ""
        ).run();

        return json({
          ok: true,
          id: result.meta.last_row_id,
          total_value: totalValue
        }, 201);
      }

      return json({
        error: "Rota não encontrada."
      }, 404);

    } catch (error) {
      console.error(error);

      return json({
        error: "Erro interno.",
        details: error.message
      }, 500);
    }
  }
};
