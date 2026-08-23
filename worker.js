const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=UTF-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS"
    }
  });

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Headers": "Content-Type",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS"
        }
      });
    }

    // =====================================================
    // TESTE DA API
    // =====================================================

    if (path === "/api/health" && request.method === "GET") {
      return json({
        ok: true,
        sistema: "Emirates Parque Flamboyant",
        banco: "D1 conectado"
      });
    }

    // =====================================================
    // FUNCIONÁRIOS
    // =====================================================

    if (path === "/api/employees" && request.method === "GET") {
      const result = await env.DB.prepare(`
        SELECT *
        FROM employees
        ORDER BY name
      `).all();

      return json(result.results || []);
    }

    if (path === "/api/employees" && request.method === "POST") {
      const body = await request.json();

      if (!body.name) {
        return json({ error: "Nome do funcionário é obrigatório." }, 400);
      }

      const result = await env.DB.prepare(`
        INSERT INTO employees
        (name, role, registration, team, company, status)
        VALUES (?, ?, ?, ?, ?, ?)
      `)
        .bind(
          body.name,
          body.role || "",
          body.registration || "",
          body.team || "",
          body.company || "TERRAL INCORPORADORA",
          body.status || "ATIVO"
        )
        .run();

      return json({
        ok: true,
        id: result.meta.last_row_id
      }, 201);
    }

    // =====================================================
    // TAREFAS
    // =====================================================

    if (path === "/api/tasks" && request.method === "GET") {
      const result = await env.DB.prepare(`
        SELECT *
        FROM tasks
        ORDER BY description
      `).all();

      return json(result.results || []);
    }

    if (path === "/api/tasks" && request.method === "POST") {
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
      `)
        .bind(
          body.description,
          body.unit,
          Number(body.unit_value || 0),
          body.active === 0 ? 0 : 1
        )
        .run();

      return json({
        ok: true,
        id: result.meta.last_row_id
      }, 201);
    }

    // =====================================================
    // CARTÃO DE PONTO
    // =====================================================

    if (path === "/api/time-entries" && request.method === "GET") {
      const result = await env.DB.prepare(`
        SELECT
          t.*,
          e.name AS employee_name
        FROM time_entries t
        JOIN employees e
          ON e.id = t.employee_id
        ORDER BY t.work_date DESC, e.name
      `).all();

      return json(result.results || []);
    }

    if (path === "/api/time-entries" && request.method === "POST") {
      const body = await request.json();

      if (!body.employee_id || !body.work_date) {
        return json({
          error: "Funcionário e data são obrigatórios."
        }, 400);
      }

      const result = await env.DB.prepare(`
        INSERT INTO time_entries
        (
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
      `)
        .bind(
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
        )
        .run();

      return json({
        ok: true,
        id: result.meta.last_row_id
      }, 201);
    }

    // =====================================================
    // PRODUÇÃO
    // =====================================================

    if (path === "/api/production" && request.method === "GET") {
      const result = await env.DB.prepare(`
        SELECT
          p.*,
          e.name AS employee_name,
          t.description AS task_description,
          t.unit AS task_unit
        FROM production_entries p
        JOIN employees e
          ON e.id = p.employee_id
        JOIN tasks t
          ON t.id = p.task_id
        ORDER BY p.work_date DESC, e.name
      `).all();

      return json(result.results || []);
    }

    if (path === "/api/production" && request.method === "POST") {
      const body = await request.json();

      if (!body.employee_id || !body.task_id || !body.work_date) {
        return json({
          error: "Funcionário, tarefa e data são obrigatórios."
        }, 400);
      }

      const quantity = Number(body.quantity || 0);
      const unitValue = Number(body.unit_value || 0);
      const totalValue = quantity * unitValue;

      const result = await env.DB.prepare(`
        INSERT INTO production_entries
        (
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
      `)
        .bind(
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
        )
        .run();

      return json({
        ok: true,
        id: result.meta.last_row_id,
        total_value: totalValue
      }, 201);
    }

    // =====================================================
    // PÁGINA INICIAL
    // =====================================================

    if (path === "/" && request.method === "GET") {
      return new Response(
        `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <title>Emirates Parque Flamboyant | Terral</title>

  <style>
    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      font-family: Arial, Helvetica, sans-serif;
      background: #f4f6f8;
      color: #1f2937;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }

    .card {
      width: 100%;
      max-width: 700px;
      background: white;
      border-radius: 18px;
      padding: 42px;
      box-shadow: 0 12px 35px rgba(0,0,0,.10);
      text-align: center;
    }

    .marca {
      color: #7b2639;
      font-weight: 800;
      letter-spacing: 1px;
      margin-bottom: 12px;
    }

    h1 {
      margin: 0 0 8px;
      font-size: 32px;
    }

    .subtitulo {
      color: #6b7280;
      margin-bottom: 32px;
    }

    .status {
      background: #f7f7f7;
      border-radius: 12px;
      padding: 18px;
      margin-bottom: 25px;
    }

    .ok {
      color: #16803c;
      font-weight: bold;
    }

    .erro {
      color: #b42318;
      font-weight: bold;
    }

    .botoes {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 12px;
    }

    button {
      border: none;
      border-radius: 10px;
      padding: 15px;
      font-size: 15px;
      font-weight: 700;
      cursor: pointer;
      background: #7b2639;
      color: white;
    }

    button:hover {
      opacity: .9;
    }

    @media (max-width: 600px) {
      .card {
        padding: 28px 20px;
      }

      .botoes {
        grid-template-columns: 1fr;
      }

      h1 {
        font-size: 26px;
      }
    }
  </style>
</head>

<body>

  <main class="card">

    <div class="marca">
      TERRAL INCORPORADORA
    </div>

    <h1>EMIRATES PARQUE FLAMBOYANT</h1>

    <div class="subtitulo">
      Controle de Ponto e Produção
    </div>

    <div class="status">
      Status do sistema:
      <span id="status">verificando...</span>
    </div>

    <div class="botoes">
      <button type="button">Funcionários</button>
      <button type="button">Cartão de Ponto</button>
      <button type="button">Produção</button>
      <button type="button">Tarefas</button>
    </div>

  </main>

  <script>
    async function verificarSistema() {
      const status = document.getElementById("status");

      try {
        const resposta = await fetch("/api/health");
        const dados = await resposta.json();

        if (dados.ok) {
          status.textContent = "ONLINE ✓";
          status.className = "ok";
        } else {
          throw new Error("API indisponível");
        }
      } catch (erro) {
        status.textContent = "ERRO";
        status.className = "erro";
      }
    }

    verificarSistema();
  </script>

</body>
</html>`,
        {
          headers: {
            "content-type": "text/html; charset=UTF-8"
          }
        }
      );
    }

    // =====================================================
    // ROTA NÃO ENCONTRADA
    // =====================================================

    return json({
      error: "Rota não encontrada."
    }, 404);
  }
};
