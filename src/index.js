const SESSION_COOKIE = "gp_session";
const SESSION_MAX_AGE = 60 * 60 * 24 * 7;

const SITE_ORIGIN = "https://globalplay.fun";
const MAX_IMAGE_BYTES = 1_500_000; // limite seguro para uma imagem no D1 (1,5 MB)

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pathname = normalizePathname(url.pathname);

    try {
      if (pathname === "/favicon.ico" || pathname === "/favicon.svg") {
        const icon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#07101e"/><path d="M14 17h17c11 0 18 5 18 15s-7 15-18 15H25v10H14V17zm11 9v12h6c5 0 7-2 7-6s-2-6-7-6h-6z" fill="#fff"/><circle cx="50" cy="14" r="7" fill="#e71c39"/></svg>`;
        return textResponse(icon, "image/svg+xml; charset=UTF-8", 86400);
      }

      // Arquivo lido pelos mecanismos de busca.
      // Mantemos o domínio canônico fixo para evitar sitemap com worker.dev ou outro host.
      if (pathname === "/robots.txt") {
        const body = [
          "User-agent: *",
          "Allow: /",
          "Disallow: /admin",
          "Disallow: /setup",
          `Sitemap: ${SITE_ORIGIN}/sitemap.xml`,
          "",
        ].join("\n");

        return textResponse(body, "text/plain; charset=UTF-8", 300);
      }

      // Sitemap XML real. Esta rota precisa responder XML, nunca a página inicial.
      if (pathname === "/sitemap.xml") {
        const body = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>${escapeXml(SITE_ORIGIN + "/")}</loc>
  </url>
</urlset>`;

        return textResponse(body, "application/xml; charset=UTF-8", 300);
      }

      if (pathname.startsWith("/media/")) {
        return serveMedia(pathname, env);
      }

      if (pathname === "/setup") {
        return handleSetup(request, env);
      }

      if (pathname === "/admin/login") {
        return handleLogin(request, env);
      }

      if (pathname === "/admin/logout") {
        return handleLogout(request, env);
      }

      if (pathname === "/admin") {
        const admin = await requireAdmin(request, env);
        if (admin instanceof Response) return admin;
        return htmlResponse(await adminDashboard(env, admin));
      }

      if (pathname === "/admin/visits") {
        const admin = await requireAdmin(request, env);
        if (admin instanceof Response) return admin;
        return htmlResponse(await visitsPage(env, admin));
      }

      if (pathname === "/admin/plans") {
        const admin = await requireAdmin(request, env);
        if (admin instanceof Response) return admin;
        return handlePlans(request, env, admin);
      }

      if (pathname === "/admin/apps") {
        const admin = await requireAdmin(request, env);
        if (admin instanceof Response) return admin;
        return handleApps(request, env, admin);
      }

      if (pathname === "/admin/site") {
        const admin = await requireAdmin(request, env);
        if (admin instanceof Response) return admin;
        return handleSite(request, env, admin);
      }

      if (pathname === "/admin/whatsapp") {
        const admin = await requireAdmin(request, env);
        if (admin instanceof Response) return admin;
        return handleWhatsapp(request, env, admin);
      }

      if (pathname === "/admin/seo") {
        const admin = await requireAdmin(request, env);
        if (admin instanceof Response) return admin;
        return handleSeo(request, env, admin);
      }

      if (pathname === "/") {
        return htmlResponse(await homePage(env, request), 200, true);
      }

      return htmlResponse(notFoundPage(), 404);
    } catch (error) {
      console.error(error);
      return htmlResponse(errorPage(error?.message || "Erro interno"), 500);
    }
  },
};

/* =========================
   SETUP INICIAL
========================= */

async function handleSetup(request, env) {
  const existing = await env.DB.prepare(
    "SELECT COUNT(*) AS total FROM admins"
  ).first();

  if (Number(existing?.total || 0) > 0) {
    return htmlResponse(
      simpleMessagePage(
        "Administrador já configurado",
        "O cadastro inicial já foi concluído.",
        "/admin/login",
        "IR PARA LOGIN"
      )
    );
  }

  if (request.method === "GET") {
    return htmlResponse(setupPage());
  }

  if (request.method !== "POST") {
    return new Response("Método não permitido", { status: 405 });
  }

  const form = await request.formData();
  const email = String(form.get("email") || "").trim().toLowerCase();
  const password = String(form.get("password") || "");
  const confirm = String(form.get("confirm") || "");

  if (!email || !email.includes("@")) {
    return htmlResponse(setupPage("Digite um e-mail válido."), 400);
  }

  if (password.length < 8) {
    return htmlResponse(
      setupPage("A senha precisa ter pelo menos 8 caracteres."),
      400
    );
  }

  if (password !== confirm) {
    return htmlResponse(setupPage("As duas senhas não são iguais."), 400);
  }

  const checkAgain = await env.DB.prepare(
    "SELECT COUNT(*) AS total FROM admins"
  ).first();

  if (Number(checkAgain?.total || 0) > 0) {
    return redirect(request, "/admin/login");
  }

  const salt = randomHex(16);
  const passwordHash = await hashPassword(password, salt);

  await env.DB.prepare(`
    INSERT INTO admins (email, password_hash, salt)
    VALUES (?, ?, ?)
  `)
    .bind(email, passwordHash, salt)
    .run();

  return htmlResponse(
    simpleMessagePage(
      "Administrador criado",
      "Seu acesso foi configurado com sucesso.",
      "/admin/login",
      "ENTRAR NO PAINEL",
      true
    )
  );
}

/* =========================
   LOGIN / SESSÃO
========================= */

async function handleLogin(request, env) {
  const currentAdmin = await getLoggedAdmin(request, env);
  if (currentAdmin) return redirect(request, "/admin");

  if (request.method === "GET") {
    return htmlResponse(loginPage());
  }

  if (request.method !== "POST") {
    return new Response("Método não permitido", { status: 405 });
  }

  const form = await request.formData();
  const email = String(form.get("email") || "").trim().toLowerCase();
  const password = String(form.get("password") || "");

  const admin = await env.DB.prepare(`
    SELECT id, email, password_hash, salt
    FROM admins
    WHERE email = ?
    LIMIT 1
  `)
    .bind(email)
    .first();

  if (!admin) {
    return htmlResponse(loginPage("E-mail ou senha incorretos."), 401);
  }

  const candidateHash = await hashPassword(password, admin.salt);

  if (!constantTimeEqual(candidateHash, admin.password_hash)) {
    return htmlResponse(loginPage("E-mail ou senha incorretos."), 401);
  }

  const sessionToken = randomHex(32);
  const storedToken = await sha256(sessionToken);
  const expires = new Date(Date.now() + SESSION_MAX_AGE * 1000).toISOString();

  await env.DB.prepare(`
    INSERT INTO sessions (token, admin_id, expires_at)
    VALUES (?, ?, ?)
  `)
    .bind(storedToken, admin.id, expires)
    .run();

  return new Response(null, {
    status: 302,
    headers: {
      Location: new URL("/admin", request.url).toString(),
      "Set-Cookie": `${SESSION_COOKIE}=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_MAX_AGE}`,
      "Cache-Control": "no-store",
    },
  });
}

async function requireAdmin(request, env) {
  const admin = await getLoggedAdmin(request, env);
  if (!admin) return redirect(request, "/admin/login");
  return admin;
}

async function getLoggedAdmin(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return null;

  const storedToken = await sha256(token);
  const session = await env.DB.prepare(`
    SELECT sessions.token, sessions.expires_at, admins.id, admins.email
    FROM sessions
    INNER JOIN admins ON admins.id = sessions.admin_id
    WHERE sessions.token = ?
    LIMIT 1
  `)
    .bind(storedToken)
    .first();

  if (!session) return null;

  if (new Date(session.expires_at).getTime() < Date.now()) {
    await env.DB.prepare("DELETE FROM sessions WHERE token = ?")
      .bind(storedToken)
      .run();
    return null;
  }

  return { id: session.id, email: session.email };
}

async function handleLogout(request, env) {
  const token = getCookie(request, SESSION_COOKIE);

  if (token) {
    const storedToken = await sha256(token);
    await env.DB.prepare("DELETE FROM sessions WHERE token = ?")
      .bind(storedToken)
      .run();
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: new URL("/admin/login", request.url).toString(),
      "Set-Cookie": `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
      "Cache-Control": "no-store",
    },
  });
}

/* =========================
   PAINEL: PLANOS
========================= */

async function handlePlans(request, env, admin) {
  if (request.method === "POST") {
    const form = await request.formData();
    const action = String(form.get("action") || "update");

    if (action === "update") {
      const id = Number(form.get("id"));
      const title = String(form.get("title") || "").trim();
      const price = String(form.get("price") || "").trim();
      const screens = String(form.get("screens") || "").trim();
      const description = String(form.get("description") || "").trim();

      if (id && title && price) {
        await env.DB.prepare(`
          UPDATE plans
          SET title = ?, price = ?, screens = ?, description = ?
          WHERE id = ?
        `)
          .bind(title, price, screens, description, id)
          .run();
      }
    }

    return redirect(request, "/admin/plans?saved=1");
  }

  const result = await env.DB.prepare(`
    SELECT id, category, title, price, screens, description
    FROM plans
    WHERE active = 1
    ORDER BY category, sort_order, id
  `).all();

  return htmlResponse(
    plansPage(
      admin,
      result.results || [],
      new URL(request.url).searchParams.get("saved")
    )
  );
}

function plansPage(admin, plans, saved) {
  const clientPlans = plans.filter((plan) => plan.category === "cliente");
  const resellerPlans = plans.filter((plan) => plan.category === "revendedor");

  const renderPlan = (plan) => `
    <form class="edit-card" method="POST">
      <input type="hidden" name="action" value="update">
      <input type="hidden" name="id" value="${Number(plan.id)}">

      <label>Nome do plano</label>
      <input name="title" value="${escapeHtml(plan.title)}" required>

      <label>Preço</label>
      <input name="price" value="${escapeHtml(plan.price)}" required>

      <label>Telas / informação curta</label>
      <input name="screens" value="${escapeHtml(plan.screens || "")}">

      <label>Descrição</label>
      <textarea name="description">${escapeHtml(plan.description || "")}</textarea>

      <button type="submit">SALVAR ALTERAÇÕES</button>
    </form>
  `;

  return adminLayout(
    "Planos",
    admin,
    `
      <h1>Editar planos</h1>
      <p class="admin-subtitle">Altere preços e informações exibidas no site.</p>
      ${saved ? successBox("Alterações salvas com sucesso.") : ""}

      <h2>Cliente final</h2>
      <div class="edit-grid">${clientPlans.map(renderPlan).join("")}</div>

      <h2 class="section-gap">Revendedores</h2>
      <div class="edit-grid">${resellerPlans.map(renderPlan).join("")}</div>
    `
  );
}

/* =========================
   PAINEL: APLICATIVOS
========================= */

async function handleApps(request, env, admin) {
  if (request.method === "POST") {
    const form = await request.formData();
    const action = String(form.get("action") || "update");

    try {
      if (action === "add") {
        const name = String(form.get("name") || "").trim();
        if (!name) throw new Error("Digite o nome do aplicativo.");

        const imageFile = form.get("image_file");
        const imageUrl = await saveUploadedImage(env, imageFile);

        const next = await env.DB.prepare(
          "SELECT COALESCE(MAX(sort_order), 0) + 1 AS next_order FROM apps"
        ).first();

        await env.DB.prepare(`
          INSERT INTO apps (name, image_url, sort_order, active)
          VALUES (?, ?, ?, 1)
        `)
          .bind(name, imageUrl, Number(next?.next_order || 1))
          .run();
      }

      if (action === "update") {
        const id = Number(form.get("id"));
        const name = String(form.get("name") || "").trim();
        const active = form.get("active") === "1" ? 1 : 0;
        if (!id || !name) throw new Error("Aplicativo inválido.");

        const current = await env.DB.prepare(
          "SELECT image_url FROM apps WHERE id = ? LIMIT 1"
        ).bind(id).first();

        let imageUrl = String(current?.image_url || "");
        const removeImage = form.get("remove_image") === "1";
        const imageFile = form.get("image_file");

        if (removeImage) {
          await deleteStoredMedia(env, imageUrl);
          imageUrl = "";
        } else if (hasUploadedFile(imageFile)) {
          const newUrl = await saveUploadedImage(env, imageFile);
          await deleteStoredMedia(env, imageUrl);
          imageUrl = newUrl;
        }

        await env.DB.prepare(`
          UPDATE apps
          SET name = ?, image_url = ?, active = ?
          WHERE id = ?
        `)
          .bind(name, imageUrl, active, id)
          .run();
      }

      if (action === "delete") {
        const id = Number(form.get("id"));
        if (id) {
          const current = await env.DB.prepare(
            "SELECT image_url FROM apps WHERE id = ? LIMIT 1"
          ).bind(id).first();
          await deleteStoredMedia(env, String(current?.image_url || ""));
          await env.DB.prepare("DELETE FROM apps WHERE id = ?").bind(id).run();
        }
      }

      return redirect(request, "/admin/apps?saved=1");
    } catch (error) {
      const result = await env.DB.prepare(`
        SELECT id, name, image_url, active
        FROM apps
        ORDER BY sort_order, id
      `).all();

      return htmlResponse(
        appsPage(admin, result.results || [], false, error?.message || "Erro ao salvar aplicativo."),
        400
      );
    }
  }

  const result = await env.DB.prepare(`
    SELECT id, name, image_url, active
    FROM apps
    ORDER BY sort_order, id
  `).all();

  return htmlResponse(
    appsPage(
      admin,
      result.results || [],
      new URL(request.url).searchParams.get("saved")
    )
  );
}

function appsPage(admin, apps, saved, error = "") {
  return adminLayout(
    "Aplicativos",
    admin,
    `
      <h1>Aplicativos parceiros</h1>
      <p class="admin-subtitle">Agora as imagens podem ser escolhidas diretamente do seu computador.</p>
      ${saved ? successBox("Aplicativos atualizados com sucesso.") : ""}
      ${error ? errorBox(error) : ""}

      <h2>Adicionar aplicativo</h2>
      <form class="edit-card compact image-upload-form" method="POST" enctype="multipart/form-data">
        <input type="hidden" name="action" value="add">
        <label>Nome</label>
        <input name="name" required>

        <label>Imagem do aplicativo</label>
        <input class="file-input" type="file" name="image_file" accept="image/png,image/jpeg,image/webp,image/gif,image/avif,image/svg+xml" data-image-upload>
        <p class="upload-status help">Escolha PNG, JPG, WEBP, GIF, AVIF ou SVG. Imagens grandes são reduzidas automaticamente no navegador.</p>

        <button type="submit">ADICIONAR APLICATIVO</button>
      </form>

      <h2 class="section-gap">Aplicativos cadastrados</h2>
      <div class="edit-grid">
        ${apps
          .map(
            (app) => `
          <div>
            <form class="edit-card image-upload-form" method="POST" enctype="multipart/form-data">
              <input type="hidden" name="id" value="${Number(app.id)}">
              <input type="hidden" name="action" value="update">

              ${imagePreview(app.image_url, app.name)}

              <label>Nome</label>
              <input name="name" value="${escapeHtml(app.name)}" required>

              <label>Trocar imagem pelo computador</label>
              <input class="file-input" type="file" name="image_file" accept="image/png,image/jpeg,image/webp,image/gif,image/avif,image/svg+xml" data-image-upload>
              <p class="upload-status help">Se não escolher outra imagem, a atual será mantida.</p>

              ${app.image_url ? `
                <label class="checkbox-row remove-image-row">
                  <input type="checkbox" name="remove_image" value="1">
                  Remover a imagem atual
                </label>
              ` : ""}

              <label class="checkbox-row">
                <input type="checkbox" name="active" value="1" ${Number(app.active) === 1 ? "checked" : ""}>
                Exibir no site
              </label>

              <button type="submit">SALVAR</button>
            </form>

            <form method="POST" class="delete-form" onsubmit="return confirm('Excluir este aplicativo?');">
              <input type="hidden" name="action" value="delete">
              <input type="hidden" name="id" value="${Number(app.id)}">
              <button class="danger" type="submit">EXCLUIR ${escapeHtml(app.name)}</button>
            </form>
          </div>
        `
          )
          .join("")}
      </div>
    `
  );
}

/* =========================
   PAINEL: SITE
========================= */

async function handleSite(request, env, admin) {
  if (request.method === "POST") {
    const form = await request.formData();

    try {
      const current = await loadSettings(env);

      await setSetting(env, "site_name", String(form.get("site_name") || "Global Play").trim());
      await setSetting(env, "hero_title", String(form.get("hero_title") || "").trim());
      await setSetting(env, "hero_text", String(form.get("hero_text") || "").trim());

      let logoUrl = String(current.logo_url || "");
      let heroBannerUrl = String(current.hero_banner_url || "");

      const logoFile = form.get("logo_file");
      const bannerFile = form.get("hero_banner_file");

      if (form.get("remove_logo") === "1") {
        await deleteStoredMedia(env, logoUrl);
        logoUrl = "";
      } else if (hasUploadedFile(logoFile)) {
        const newLogo = await saveUploadedImage(env, logoFile);
        await deleteStoredMedia(env, logoUrl);
        logoUrl = newLogo;
      }

      if (form.get("remove_hero_banner") === "1") {
        await deleteStoredMedia(env, heroBannerUrl);
        heroBannerUrl = "";
      } else if (hasUploadedFile(bannerFile)) {
        const newBanner = await saveUploadedImage(env, bannerFile);
        await deleteStoredMedia(env, heroBannerUrl);
        heroBannerUrl = newBanner;
      }

      await setSetting(env, "logo_url", logoUrl);
      await setSetting(env, "hero_banner_url", heroBannerUrl);

      return redirect(request, "/admin/site?saved=1");
    } catch (error) {
      const settings = await loadSettings(env);
      return htmlResponse(
        sitePage(admin, settings, false, error?.message || "Erro ao salvar o site."),
        400
      );
    }
  }

  const settings = await loadSettings(env);
  return htmlResponse(
    sitePage(admin, settings, new URL(request.url).searchParams.get("saved"))
  );
}

function sitePage(admin, settings, saved, error = "") {
  return adminLayout(
    "Site",
    admin,
    `
      <h1>Editar site</h1>
      <p class="admin-subtitle">Troque a logo e o banner selecionando arquivos do seu computador. Não precisa mais colar URL.</p>
      ${saved ? successBox("Configurações do site salvas.") : ""}
      ${error ? errorBox(error) : ""}

      <form class="edit-card wide image-upload-form" method="POST" enctype="multipart/form-data">
        <label>Nome do site</label>
        <input name="site_name" value="${escapeHtml(settings.site_name || "Global Play")}">

        <label>Título principal</label>
        <input name="hero_title" value="${escapeHtml(settings.hero_title || "")}">

        <label>Texto principal</label>
        <textarea name="hero_text">${escapeHtml(settings.hero_text || "")}</textarea>

        <div class="media-editor">
          <h3>Logo do site</h3>
          ${imagePreview(settings.logo_url, "Logo atual")}
          <label>Escolher nova logo no computador</label>
          <input class="file-input" type="file" name="logo_file" accept="image/png,image/jpeg,image/webp,image/gif,image/avif,image/svg+xml" data-image-upload>
          <p class="upload-status help">Se não escolher arquivo, a logo atual permanece.</p>
          ${settings.logo_url ? `
            <label class="checkbox-row remove-image-row">
              <input type="checkbox" name="remove_logo" value="1">
              Remover a logo atual
            </label>
          ` : ""}
        </div>

        <div class="media-editor">
          <h3>Banner principal</h3>
          ${imagePreview(settings.hero_banner_url, "Banner atual", true)}
          <label>Escolher novo banner no computador</label>
          <input class="file-input" type="file" name="hero_banner_file" accept="image/png,image/jpeg,image/webp,image/gif,image/avif,image/svg+xml" data-image-upload>
          <p class="upload-status help">Imagens grandes são reduzidas automaticamente antes do envio.</p>
          ${settings.hero_banner_url ? `
            <label class="checkbox-row remove-image-row">
              <input type="checkbox" name="remove_hero_banner" value="1">
              Remover o banner atual
            </label>
          ` : ""}
        </div>

        <button type="submit">SALVAR SITE</button>
      </form>
    `
  );
}

/* =========================
   PAINEL: WHATSAPP
========================= */

async function handleWhatsapp(request, env, admin) {
  if (request.method === "POST") {
    const form = await request.formData();
    const raw = String(form.get("whatsapp") || "").trim();
    const number = raw.replace(/\D/g, "");

    if (number.length < 10) {
      const settings = await loadSettings(env);
      return htmlResponse(whatsappPage(admin, settings, false, "Digite um número válido."), 400);
    }

    await setSetting(env, "whatsapp", number);
    return redirect(request, "/admin/whatsapp?saved=1");
  }

  const settings = await loadSettings(env);
  return htmlResponse(
    whatsappPage(
      admin,
      settings,
      new URL(request.url).searchParams.get("saved")
    )
  );
}

function whatsappPage(admin, settings, saved, error = "") {
  return adminLayout(
    "WhatsApp",
    admin,
    `
      <h1>WhatsApp</h1>
      <p class="admin-subtitle">Este número será usado nos botões do site.</p>
      ${saved ? successBox("Número do WhatsApp salvo.") : ""}
      ${error ? errorBox(error) : ""}

      <form class="edit-card compact" method="POST">
        <label>Número com DDI e DDD</label>
        <input name="whatsapp" value="${escapeHtml(settings.whatsapp || "")}" placeholder="5521999999999" required>
        <p class="help">Exemplo: 55 + DDD + número, sem espaços.</p>
        <button type="submit">SALVAR WHATSAPP</button>
      </form>
    `
  );
}

/* =========================
   PAINEL: SEO
========================= */

async function handleSeo(request, env, admin) {
  if (request.method === "POST") {
    const form = await request.formData();
    await setSetting(env, "seo_title", String(form.get("seo_title") || "").trim());
    await setSetting(env, "seo_description", String(form.get("seo_description") || "").trim());
    await setSetting(env, "seo_social_image", safeUrl(form.get("seo_social_image") || ""));
    return redirect(request, "/admin/seo?saved=1");
  }

  const settings = await loadSettings(env);
  return htmlResponse(
    seoPage(admin, settings, new URL(request.url).searchParams.get("saved"))
  );
}

function seoPage(admin, settings, saved) {
  return adminLayout(
    "SEO",
    admin,
    `
      <h1>Google / SEO</h1>
      <p class="admin-subtitle">Edite o título e a descrição que ajudam o Google a entender seu site.</p>
      ${saved ? successBox("SEO salvo com sucesso.") : ""}

      <form class="edit-card wide" method="POST">
        <label>Título SEO</label>
        <input name="seo_title" maxlength="70" value="${escapeHtml(settings.seo_title || "")}">

        <label>Descrição SEO</label>
        <textarea name="seo_description" maxlength="180">${escapeHtml(settings.seo_description || "")}</textarea>

        <label>Imagem para compartilhamento (opcional)</label>
        <input name="seo_social_image" value="${escapeHtml(settings.seo_social_image || "")}" placeholder="https://...">
        <p class="help">Usada por WhatsApp, Facebook, X e outros previews. Se ficar vazia, o banner principal será usado.</p>

        <button type="submit">SALVAR SEO</button>
      </form>

      <div class="panel-card section-gap">
        <h3>SEO técnico</h3>
        <p><strong>Sitemap:</strong> /sitemap.xml · <strong>Robots:</strong> /robots.txt · <strong>Canonical:</strong> https://globalplay.fun/</p>
        <p class="help">A página pública também envia Open Graph, Twitter Card e dados estruturados Schema.org automaticamente.</p>
      </div>
    `
  );
}

/* =========================
   PAINEL: VISÃO GERAL
========================= */

async function adminDashboard(env, admin) {
  const stats = await getVisitStats(env);

  return adminLayout(
    "Visão geral",
    admin,
    `
      <h1>Painel Global Play</h1>
      <p class="admin-subtitle">Bem-vindo, <strong>${escapeHtml(admin.email)}</strong></p>

      <div class="stats-grid">
        <div class="stat-card">
          <span class="stat-label">Visitas totais</span>
          <strong class="stat-number">${stats.total.toLocaleString("pt-BR")}</strong>
          <span class="stat-help">Acessos registrados desde a ativação do contador</span>
        </div>
        <div class="stat-card">
          <span class="stat-label">Visitas hoje</span>
          <strong class="stat-number">${stats.today.toLocaleString("pt-BR")}</strong>
          <span class="stat-help">Data considerada: horário de Brasília</span>
        </div>
        <div class="stat-card">
          <span class="stat-label">Ontem</span>
          <strong class="stat-number">${stats.yesterday.toLocaleString("pt-BR")}</strong>
          <span class="stat-help">Acessos registrados no dia anterior</span>
        </div>
        <div class="stat-card">
          <span class="stat-label">Últimos 7 dias</span>
          <strong class="stat-number">${stats.last7.toLocaleString("pt-BR")}</strong>
          <span class="stat-help">Soma dos acessos dos últimos sete dias</span>
        </div>
        <div class="stat-card">
          <span class="stat-label">Últimos 30 dias</span>
          <strong class="stat-number">${stats.last30.toLocaleString("pt-BR")}</strong>
          <span class="stat-help">Soma dos acessos dos últimos trinta dias</span>
        </div>
      </div>

      <div class="cards">
        <a class="panel-card link-card visits-highlight" href="/admin/visits">
          <h3>📊 Visitas</h3>
          <p>Ver histórico diário, hoje, ontem, 7 dias, 30 dias e total.</p>
        </a>
        <a class="panel-card link-card" href="/admin/plans">
          <h3>Planos</h3>
          <p>Editar preços, períodos, telas e descrições.</p>
        </a>
        <a class="panel-card link-card" href="/admin/apps">
          <h3>Aplicativos</h3>
          <p>Adicionar, editar, ocultar ou excluir aplicativos parceiros.</p>
        </a>
        <a class="panel-card link-card" href="/admin/site">
          <h3>Site</h3>
          <p>Alterar textos principais, logo e banner.</p>
        </a>
        <a class="panel-card link-card" href="/admin/whatsapp">
          <h3>WhatsApp</h3>
          <p>Trocar o número usado nos botões do site.</p>
        </a>
        <a class="panel-card link-card" href="/admin/seo">
          <h3>Google / SEO</h3>
          <p>Editar título, descrição e conferir o sitemap.</p>
        </a>
        <a class="panel-card link-card" href="/" target="_blank">
          <h3>Ver site</h3>
          <p>Abrir a página pública em outra aba.</p>
        </a>
      </div>
    `
  );
}

/* =========================
   PAINEL: VISITAS
========================= */

async function visitsPage(env, admin) {
  await ensureVisitTable(env);
  const stats = await getVisitStats(env);
  const historyResult = await env.DB.prepare(`
    SELECT day, visits
    FROM analytics_daily
    ORDER BY day DESC
    LIMIT 30
  `).all();

  const history = historyResult.results || [];
  const rows = history.length
    ? history.map((row) => `
        <tr>
          <td>${escapeHtml(formatBrazilDate(row.day))}</td>
          <td><strong>${Number(row.visits || 0).toLocaleString("pt-BR")}</strong></td>
        </tr>
      `).join("")
    : `<tr><td colspan="2" class="empty-table">Nenhuma visita registrada ainda.</td></tr>`;

  return adminLayout(
    "Visitas",
    admin,
    `
      <div class="page-heading-row">
        <div>
          <h1>Visitas do site</h1>
          <p class="admin-subtitle">Acompanhe os acessos registrados no site público.</p>
        </div>
        <a class="refresh-btn" href="/admin/visits">ATUALIZAR</a>
      </div>

      <div class="stats-grid">
        <div class="stat-card">
          <span class="stat-label">Visitas totais</span>
          <strong class="stat-number">${stats.total.toLocaleString("pt-BR")}</strong>
          <span class="stat-help">Desde a ativação do contador</span>
        </div>
        <div class="stat-card">
          <span class="stat-label">Hoje</span>
          <strong class="stat-number">${stats.today.toLocaleString("pt-BR")}</strong>
          <span class="stat-help">Horário de Brasília</span>
        </div>
        <div class="stat-card">
          <span class="stat-label">Ontem</span>
          <strong class="stat-number">${stats.yesterday.toLocaleString("pt-BR")}</strong>
          <span class="stat-help">Dia anterior</span>
        </div>
        <div class="stat-card">
          <span class="stat-label">Últimos 7 dias</span>
          <strong class="stat-number">${stats.last7.toLocaleString("pt-BR")}</strong>
          <span class="stat-help">Soma dos últimos sete dias</span>
        </div>
        <div class="stat-card">
          <span class="stat-label">Últimos 30 dias</span>
          <strong class="stat-number">${stats.last30.toLocaleString("pt-BR")}</strong>
          <span class="stat-help">Soma dos últimos trinta dias</span>
        </div>
      </div>

      <div class="panel-card section-gap visits-history">
        <h3>Histórico dos últimos 30 dias</h3>
        <div class="table-wrap">
          <table class="visits-table">
            <thead><tr><th>Data</th><th>Visitas</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </div>

      <p class="help">O contador registra acessos à página inicial. Robôs e crawlers comuns são ignorados.</p>
    `
  );
}

function formatBrazilDate(day) {
  const value = String(day || "");
  const match = value.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  return match ? `${match[3]}/${match[2]}/${match[1]}` : value;
}

/* =========================
   SITE PÚBLICO
========================= */

async function homePage(env, request) {
  await recordVisit(env, request);

  const [settings, plansResult, appsResult, faqResult] = await Promise.all([
    loadSettings(env),
    env.DB.prepare(`
      SELECT id, category, title, price, screens, description
      FROM plans
      WHERE active = 1
      ORDER BY category, sort_order, id
    `).all(),
    env.DB.prepare(`
      SELECT id, name, image_url
      FROM apps
      WHERE active = 1
      ORDER BY sort_order, id
    `).all(),
    env.DB.prepare(`
      SELECT id, question, answer
      FROM faq
      WHERE active = 1
      ORDER BY sort_order, id
    `).all(),
  ]);

  const plans = plansResult.results || [];
  const apps = appsResult.results || [];
  const faq = faqResult.results || [];

  const clientPlans = plans.filter((p) => p.category === "cliente");
  const resellerPlans = plans.filter((p) => p.category === "revendedor");

  const whatsapp = String(settings.whatsapp || "5521964816185").replace(/\D/g, "");
  const logoUrl = safeUrl(settings.logo_url || "");
  const heroBannerUrl = safeUrl(settings.hero_banner_url || "");
  const seoTitle = String(settings.seo_title || "Global Play | Streaming, Filmes, Séries e Entretenimento").trim();
  const seoDescription = String(
    settings.seo_description ||
    "Conheça a Global Play: streaming, filmes, séries e entretenimento. Confira planos, dispositivos compatíveis e tire suas dúvidas pelo WhatsApp."
  ).trim();
  const canonicalUrl = SITE_ORIGIN + "/";
  const socialImage = safeUrl(settings.seo_social_image || "") || heroBannerUrl || logoUrl;
  const structuredData = JSON.stringify({
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "Organization",
        "@id": SITE_ORIGIN + "/#organization",
        name: String(settings.site_name || "Global Play"),
        url: canonicalUrl,
        ...(logoUrl ? { logo: logoUrl } : {}),
        contactPoint: [{
          "@type": "ContactPoint",
          contactType: "customer service",
          telephone: "+" + whatsapp,
          availableLanguage: ["pt-BR"]
        }]
      },
      {
        "@type": "WebSite",
        "@id": SITE_ORIGIN + "/#website",
        url: canonicalUrl,
        name: String(settings.site_name || "Global Play"),
        inLanguage: "pt-BR",
        publisher: { "@id": SITE_ORIGIN + "/#organization" }
      },
      {
        "@type": "Service",
        "@id": SITE_ORIGIN + "/#service",
        name: "Global Play",
        serviceType: "Streaming e entretenimento digital",
        areaServed: { "@type": "Country", name: "Brasil" },
        provider: { "@id": SITE_ORIGIN + "/#organization" },
        url: canonicalUrl,
        description: seoDescription
      }
    ]
  }).replace(/</g, "\\u003c");

  const planCard = (plan) => {
    const message = encodeURIComponent(
      `Olá! Quero saber mais sobre ${plan.title} - R$ ${plan.price}${plan.screens ? ` - ${plan.screens}` : ""}.`
    );

    return `
      <article class="plan-card">
        <div class="plan-kicker">${plan.category === "cliente" ? "CLIENTE FINAL" : "REVENDEDOR"}</div>
        <h3>${escapeHtml(plan.title)}</h3>
        <div class="price">R$ ${escapeHtml(plan.price)}</div>
        ${plan.screens ? `<div class="screens">${escapeHtml(plan.screens)}</div>` : ""}
        <p>${escapeHtml(plan.description || "")}</p>
        <a class="primary-btn full" href="https://wa.me/${whatsapp}?text=${message}" target="_blank" rel="noopener">ESCOLHER</a>
      </article>
    `;
  };

  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escapeHtml(seoTitle)}</title>
  <meta name="description" content="${escapeHtml(seoDescription)}">
  <meta name="robots" content="index,follow,max-image-preview:large">
  <meta name="theme-color" content="#07101e">
  <link rel="canonical" href="${escapeHtml(canonicalUrl)}">
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <meta property="og:type" content="website">
  <meta property="og:locale" content="pt_BR">
  <meta property="og:site_name" content="${escapeHtml(settings.site_name || "Global Play")}">
  <meta property="og:title" content="${escapeHtml(seoTitle)}">
  <meta property="og:description" content="${escapeHtml(seoDescription)}">
  <meta property="og:url" content="${escapeHtml(canonicalUrl)}">
  ${socialImage ? `<meta property="og:image" content="${escapeHtml(socialImage)}">` : ""}
  <meta name="twitter:card" content="${socialImage ? "summary_large_image" : "summary"}">
  <meta name="twitter:title" content="${escapeHtml(seoTitle)}">
  <meta name="twitter:description" content="${escapeHtml(seoDescription)}">
  ${socialImage ? `<meta name="twitter:image" content="${escapeHtml(socialImage)}">` : ""}
  <script type="application/ld+json">${structuredData}</script>
  <style>${publicCss()}</style>
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/">
      ${logoUrl ? `<img src="${escapeHtml(logoUrl)}" alt="Global Play">` : `<span>GLOBAL <b>PLAY</b></span>`}
    </a>
    <nav>
      <a href="#planos">Planos</a>
      <a href="#revendedores">Revendedores</a>
      <a href="#dispositivos">Dispositivos</a>
      <a href="#aplicativos">Aplicativos</a>
      <a href="#duvidas">Dúvidas</a>
    </nav>
    <a class="primary-btn small" href="#planos">Conhecer planos</a>
  </header>

  <section class="hero" ${heroBannerUrl ? `style="background-image:linear-gradient(90deg,rgba(2,8,20,.96),rgba(2,8,20,.55)),url('${escapeCssUrl(heroBannerUrl)}')"` : ""}>
    <div class="hero-copy">
      <div class="eyebrow">GLOBAL PLAY</div>
      <h1>${escapeHtml(settings.hero_title || "Global Play: filmes, séries e entretenimento por streaming")}</h1>
      <p>${escapeHtml(settings.hero_text || "Conheça os planos da Global Play para assistir a filmes, séries e TV ao vivo. Compare opções e consulte pelo WhatsApp a compatibilidade com Smart TV, celular, tablet ou computador.")}</p>
      <div class="hero-actions">
        <a class="primary-btn" href="#planos">CONHECER PLANOS</a>
        <a class="ghost-btn" href="https://wa.me/${whatsapp}" target="_blank" rel="noopener">FALAR NO WHATSAPP</a>
      </div>
    </div>
  </section>

  <section class="section" id="dispositivos">
    <div class="section-heading">
      <span>POR QUE ESCOLHER</span>
      <h2>Streaming pensado para ser simples</h2>
      <p>Menos tempo procurando, mais tempo aproveitando.</p>
    </div>
    <div class="feature-grid">
      <article class="feature"><h3>Imagem envolvente</h3><p>Experiência visual preparada para valorizar cada cena, partida e momento.</p></article>
      <article class="feature"><h3>Acesso prático</h3><p>Navegação simples para encontrar o que você quer sem etapas desnecessárias.</p></article>
      <article class="feature"><h3>Atendimento humano</h3><p>Orientação próxima para configuração e dúvidas quando você precisar.</p></article>
      <article class="feature"><h3>Vários dispositivos</h3><p>Smart TV, celular, tablet e computador em aparelhos compatíveis.</p></article>
    </div>
  </section>

  <section class="section alt" id="aplicativos">
    <div class="section-heading">
      <span>APLICATIVOS</span>
      <h2>Nossos aplicativos parceiros</h2>
      <p>Confira as opções cadastradas no painel.</p>
    </div>
    <div class="apps-grid">
      ${apps.map((app) => `<div class="app-chip">${app.image_url ? `<img src="${escapeHtml(safeUrl(app.image_url))}" alt="${escapeHtml(app.name)}">` : ""}<span>${escapeHtml(app.name)}</span></div>`).join("")}
    </div>
  </section>

  <section class="section" id="planos">
    <div class="section-heading">
      <span>CLIENTE FINAL</span>
      <h2>Escolha seu plano</h2>
      <p>Selecione o período e a quantidade de telas.</p>
    </div>
    <div class="plans-grid">${clientPlans.map(planCard).join("")}</div>
  </section>

  <section class="section alt" id="revendedores">
    <div class="section-heading">
      <span>SEJA REVENDEDOR</span>
      <h2>Abra seu painel Global Play</h2>
      <p>Conheça as opções disponíveis para revenda.</p>
    </div>
    <div class="plans-grid">${resellerPlans.map(planCard).join("")}</div>
  </section>

  <section class="section" id="duvidas">
    <div class="section-heading">
      <span>PERGUNTAS FREQUENTES</span>
      <h2>Antes de começar</h2>
    </div>
    <div class="faq-list">
      ${faq.map((item) => `<details><summary>${escapeHtml(item.question)}</summary><p>${escapeHtml(item.answer)}</p></details>`).join("")}
    </div>
  </section>

  <footer>
    <strong>${escapeHtml(settings.site_name || "Global Play")}</strong>
    <span>© 2026. Todos os direitos reservados.</span>
  </footer>

  <a class="floating-whatsapp" href="https://wa.me/${whatsapp}" target="_blank" rel="noopener">WhatsApp</a>
</body>
</html>`;
}

function publicCss() {
  return `
    *{box-sizing:border-box} html{scroll-behavior:smooth} body{margin:0;background:#020814;color:#fff;font-family:Arial,Helvetica,sans-serif} a{color:inherit}.topbar{position:sticky;top:0;z-index:20;display:flex;align-items:center;justify-content:space-between;gap:25px;padding:18px 6%;background:rgba(2,8,20,.94);backdrop-filter:blur(12px);border-bottom:1px solid #142640}.brand{text-decoration:none;font-size:26px;font-weight:900;letter-spacing:.5px}.brand b{color:#eb1d3b}.brand img{height:56px;max-width:160px;object-fit:contain}.topbar nav{display:flex;gap:24px}.topbar nav a{text-decoration:none;color:#c8d5e7;font-size:14px}.primary-btn,.ghost-btn{display:inline-block;text-decoration:none;font-weight:800;border-radius:10px;padding:15px 22px}.primary-btn{background:#df1833;color:#fff}.primary-btn.small{padding:12px 17px;font-size:14px}.primary-btn.full{width:100%;text-align:center}.ghost-btn{border:1px solid #315074;color:#dce8f7;background:rgba(6,20,42,.55)}.hero{min-height:72vh;display:flex;align-items:center;padding:80px 8%;background:radial-gradient(circle at 72% 35%,#0b3b82 0%,transparent 33%),linear-gradient(135deg,#020611,#07162d);background-size:cover;background-position:center}.hero-copy{max-width:780px}.eyebrow,.section-heading span,.plan-kicker{font-size:12px;font-weight:900;letter-spacing:2px;color:#57a0ff}.hero h1{font-size:clamp(42px,6vw,78px);line-height:1.02;margin:14px 0 22px}.hero p{font-size:20px;line-height:1.65;color:#c3d0e4;max-width:690px}.hero-actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:28px}.section{padding:75px 7%}.section.alt{background:#06101f}.section-heading{text-align:center;max-width:760px;margin:0 auto 38px}.section-heading h2{font-size:38px;margin:10px 0}.section-heading p{color:#93a7c2;line-height:1.6}.feature-grid,.plans-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(235px,1fr));gap:20px}.feature,.plan-card{background:linear-gradient(145deg,#0a1930,#0e223f);border:1px solid #1c3c66;border-radius:16px;padding:25px}.feature p,.plan-card p{color:#9eb0c8;line-height:1.55}.price{font-size:36px;font-weight:900;margin:18px 0 5px}.screens{color:#d8e4f2;font-weight:700;margin-bottom:14px}.apps-grid{display:flex;flex-wrap:wrap;gap:12px;justify-content:center}.app-chip{display:flex;align-items:center;gap:10px;padding:12px 16px;border:1px solid #22446f;background:#0a1a31;border-radius:12px}.app-chip img{width:34px;height:34px;object-fit:contain;border-radius:7px}.faq-list{max-width:900px;margin:0 auto}.faq-list details{background:#0a1930;border:1px solid #1c3c66;border-radius:12px;padding:18px 20px;margin-bottom:12px}.faq-list summary{cursor:pointer;font-weight:800}.faq-list p{color:#9eb0c8;line-height:1.6}footer{display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap;padding:34px 7%;border-top:1px solid #142640;color:#7f94af}.floating-whatsapp{position:fixed;right:22px;bottom:22px;background:#20b95e;color:#fff;text-decoration:none;font-weight:900;padding:15px 20px;border-radius:40px;box-shadow:0 12px 35px rgba(0,0,0,.35)}@media(max-width:850px){.topbar nav{display:none}.primary-btn.small{display:none}}@media(max-width:600px){.hero{padding:60px 6%;min-height:64vh}.section{padding:60px 6%}.section-heading h2{font-size:31px}.floating-whatsapp{right:14px;bottom:14px}}
  `;
}

/* =========================
   LAYOUT ADMIN
========================= */

function adminLayout(title, admin, content) {
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escapeHtml(title)} | Painel Global Play</title>
  <meta name="robots" content="noindex,nofollow,noarchive">
  <style>${adminCss()}</style>
</head>
<body>
  <div class="admin-shell">
    <aside>
      <div class="admin-brand">GLOBAL <span>PLAY</span></div>
      <nav>
        <a href="/admin">Visão geral</a>
        <a href="/admin/visits">Visitas</a>
        <a href="/admin/plans">Planos</a>
        <a href="/admin/apps">Aplicativos</a>
        <a href="/admin/site">Site</a>
        <a href="/admin/whatsapp">WhatsApp</a>
        <a href="/admin/seo">SEO</a>
        <a href="/" target="_blank">Ver site</a>
        <a href="/admin/logout">Sair</a>
      </nav>
      <div class="admin-email">${escapeHtml(admin.email)}</div>
    </aside>
    <main>${content}</main>
  </div>
  <script>${adminUploadScript()}</script>
</body>
</html>`;
}

function adminCss() {
  return `
    *{box-sizing:border-box} body{margin:0;background:#081426;color:#fff;font-family:Arial,Helvetica,sans-serif}.admin-shell{min-height:100vh;display:flex}aside{width:240px;background:#05101f;border-right:1px solid #203652;padding:30px 20px;position:fixed;inset:0 auto 0 0}.admin-brand{font-size:23px;font-weight:900;margin-bottom:28px}.admin-brand span{color:#e71c39}aside nav a{display:block;color:#cad6e8;padding:12px;border-radius:8px;text-decoration:none;margin-bottom:4px}aside nav a:hover{background:#12243e}.admin-email{position:absolute;bottom:25px;left:20px;right:20px;color:#6f86a4;font-size:12px;word-break:break-all}main{margin-left:240px;flex:1;padding:42px;max-width:1500px}.admin-subtitle,.help{color:#91a5bf;line-height:1.6}.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:18px;margin:26px 0 8px}.stat-card{background:linear-gradient(145deg,#122744,#0b1a30);border:1px solid #315b8d;border-radius:16px;padding:24px;box-shadow:0 12px 30px rgba(0,0,0,.18)}.stat-label{display:block;color:#9fb2ca;font-size:14px;font-weight:800;text-transform:uppercase;letter-spacing:.5px}.stat-number{display:block;font-size:42px;line-height:1.1;margin:10px 0 8px;color:#fff}.stat-help{display:block;color:#7188a6;font-size:12px;line-height:1.45}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:20px;margin-top:28px}.panel-card,.edit-card{background:#102039;border:1px solid #24466f;border-radius:14px;padding:24px}.link-card{text-decoration:none;color:#fff;transition:.15s}.link-card:hover{transform:translateY(-2px);border-color:#3b70aa}.visits-highlight{border-color:#2f78bd;background:linear-gradient(145deg,#15385f,#102039)}.panel-card p{color:#9fb2ca;line-height:1.55}.edit-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(290px,1fr));gap:20px;margin-top:18px}.edit-card.compact{max-width:650px}.edit-card.wide{max-width:900px}label{display:block;margin:15px 0 7px;color:#c0cfe2;font-size:14px}input,textarea{width:100%;padding:13px 14px;border-radius:8px;border:1px solid #315276;background:#07101f;color:#fff;outline:none}textarea{min-height:110px;resize:vertical}button{width:100%;margin-top:18px;padding:14px;border:0;border-radius:8px;background:#df1833;color:#fff;font-weight:900;cursor:pointer}.danger{background:#5e1722}.delete-form{margin-top:-8px}.checkbox-row{display:flex;align-items:center;gap:9px}.checkbox-row input{width:auto}.section-gap{margin-top:42px}.saved-message,.error-message{padding:14px 16px;border-radius:9px;margin:20px 0}.saved-message{background:#123d2a;border:1px solid #22764b;color:#91efb9}.error-message{background:#551522;border:1px solid #a82c42;color:#ffd0d8}.page-heading-row{display:flex;align-items:flex-start;justify-content:space-between;gap:20px}.refresh-btn{display:inline-block;text-decoration:none;background:#1f5f9d;border:1px solid #3c78b6;color:#fff;font-weight:900;padding:12px 18px;border-radius:9px}.visits-history{max-width:900px}.table-wrap{overflow-x:auto}.visits-table{width:100%;border-collapse:collapse;margin-top:12px}.visits-table th,.visits-table td{text-align:left;padding:14px 12px;border-bottom:1px solid #24466f}.visits-table th{color:#91a5bf;font-size:13px;text-transform:uppercase;letter-spacing:.5px}.visits-table td{color:#e6eef9}.empty-table{text-align:center!important;color:#91a5bf!important;padding:28px!important}.file-input{padding:10px;background:#081426;border:1px dashed #3d638f;cursor:pointer}.file-input::file-selector-button{border:0;border-radius:7px;padding:9px 12px;margin-right:10px;background:#235c96;color:#fff;font-weight:800;cursor:pointer}.media-editor{margin-top:24px;padding-top:20px;border-top:1px solid #24466f}.media-preview{display:flex;align-items:center;justify-content:center;min-height:110px;margin:10px 0 14px;padding:12px;background:#081426;border:1px solid #24466f;border-radius:10px;overflow:hidden}.media-preview img{display:block;max-width:100%;max-height:180px;object-fit:contain;border-radius:8px}.media-preview.banner img{width:100%;max-height:260px;object-fit:cover}.media-preview.empty{color:#6f86a4;font-size:13px}.remove-image-row{margin-top:12px;color:#ffb8c3}.upload-status.processing{color:#ffd37a}.upload-status.ready{color:#91efb9}.upload-status.error{color:#ff9aaa}button[disabled]{opacity:.55;cursor:not-allowed}@media(max-width:780px){aside{position:static;width:100%;height:auto}.admin-shell{display:block}.admin-email{position:static;margin-top:20px}main{margin-left:0;padding:25px}.page-heading-row{display:block}.refresh-btn{margin-top:8px}}
  `;
}

/* =========================
   TELAS DE LOGIN / SETUP
========================= */

function setupPage(error = "") {
  return authLayout(
    "Configuração inicial",
    `
      <h1>GLOBAL <span>PLAY</span></h1>
      <h2>Configuração inicial</h2>
      <p>Crie o primeiro administrador do site.</p>
      ${error ? errorBox(error) : ""}
      <form method="POST">
        <label>E-mail</label>
        <input type="email" name="email" required autocomplete="email">
        <label>Senha</label>
        <input type="password" name="password" minlength="8" required autocomplete="new-password">
        <label>Confirmar senha</label>
        <input type="password" name="confirm" minlength="8" required autocomplete="new-password">
        <button type="submit">CRIAR ADMINISTRADOR</button>
      </form>
      <small>A senha é armazenada como hash, não em texto aberto.</small>
    `
  );
}

function loginPage(error = "") {
  return authLayout(
    "Login",
    `
      <h1>GLOBAL <span>PLAY</span></h1>
      <h2>Painel administrativo</h2>
      ${error ? errorBox(error) : ""}
      <form method="POST">
        <label>E-mail</label>
        <input type="email" name="email" required autocomplete="email">
        <label>Senha</label>
        <input type="password" name="password" required autocomplete="current-password">
        <button type="submit">ENTRAR</button>
      </form>
    `
  );
}

function authLayout(title, content) {
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escapeHtml(title)} | Global Play</title>
  <meta name="robots" content="noindex,nofollow,noarchive">
  <style>
    *{box-sizing:border-box} body{margin:0;background:#07101e;color:#fff;font-family:Arial,Helvetica,sans-serif}.center{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:25px}.auth-card{width:390px;max-width:100%;background:#0d1b30;padding:35px;border-radius:18px;border:1px solid #213c61;box-shadow:0 20px 60px rgba(0,0,0,.35)}h1{text-align:center;margin-top:0}h1 span{color:#e71c39}h2{text-align:center}p,small{color:#96a8c1;line-height:1.5}label{display:block;margin-top:17px;margin-bottom:7px;font-size:14px}input{width:100%;padding:14px;border-radius:8px;border:1px solid #29496f;background:#07101e;color:white;outline:none}button,.button{display:block;width:100%;border:0;background:#df1833;color:white;padding:15px;border-radius:8px;font-weight:800;margin-top:22px;cursor:pointer;text-decoration:none;text-align:center}.success{font-size:55px;text-align:center;color:#22c66c}.error-message{background:#551522;border:1px solid #a82c42;padding:12px;border-radius:8px;margin:15px 0;color:#ffd0d8}
  </style>
</head>
<body><div class="center"><div class="auth-card">${content}</div></div></body>
</html>`;
}

function simpleMessagePage(title, text, href, buttonText, success = false) {
  return authLayout(
    title,
    `
      ${success ? '<div class="success">✓</div>' : ""}
      <h1>GLOBAL <span>PLAY</span></h1>
      <h2>${escapeHtml(title)}</h2>
      <p>${escapeHtml(text)}</p>
      <a class="button" href="${escapeHtml(href)}">${escapeHtml(buttonText)}</a>
    `
  );
}

/* =========================
   BANCO / UTILIDADES
========================= */

async function loadSettings(env) {
  const result = await env.DB.prepare("SELECT key, value FROM settings").all();
  const settings = {};
  for (const row of result.results || []) settings[row.key] = row.value;
  return settings;
}

async function setSetting(env, key, value) {
  await env.DB.prepare(`
    INSERT INTO settings (key, value)
    VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `)
    .bind(key, value)
    .run();
}


/* =========================
   IMAGENS ENVIADAS PELO PC
========================= */

async function ensureMediaTable(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS media_files (
      id TEXT PRIMARY KEY,
      filename TEXT,
      mime_type TEXT NOT NULL,
      data BLOB NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
}

function hasUploadedFile(value) {
  return Boolean(
    value &&
    typeof value === "object" &&
    typeof value.arrayBuffer === "function" &&
    Number(value.size || 0) > 0
  );
}

async function saveUploadedImage(env, file) {
  if (!hasUploadedFile(file)) return "";

  const allowedTypes = new Set([
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/gif",
    "image/avif",
    "image/svg+xml",
  ]);

  const type = String(file.type || "").toLowerCase();
  if (!allowedTypes.has(type)) {
    throw new Error("Formato de imagem não aceito. Use PNG, JPG, WEBP, GIF, AVIF ou SVG.");
  }

  const buffer = await file.arrayBuffer();
  if (buffer.byteLength > MAX_IMAGE_BYTES) {
    throw new Error("A imagem ficou maior que 1,5 MB. Aguarde a redução automática ou escolha uma imagem menor.");
  }

  await ensureMediaTable(env);
  const id = randomHex(16);

  await env.DB.prepare(`
    INSERT INTO media_files (id, filename, mime_type, data)
    VALUES (?, ?, ?, ?)
  `)
    .bind(id, String(file.name || "imagem"), type, buffer)
    .run();

  return `/media/${id}`;
}

async function serveMedia(pathname, env) {
  const match = String(pathname || "").match(/^\/media\/([a-f0-9]{32})$/i);
  if (!match) return new Response("Imagem não encontrada", { status: 404 });

  await ensureMediaTable(env);
  const row = await env.DB.prepare(`
    SELECT mime_type, data
    FROM media_files
    WHERE id = ?
    LIMIT 1
  `).bind(match[1]).first();

  if (!row || !row.data) {
    return new Response("Imagem não encontrada", { status: 404 });
  }

  return new Response(new Uint8Array(row.data), {
    status: 200,
    headers: {
      "Content-Type": String(row.mime_type || "application/octet-stream"),
      "Cache-Control": "public, max-age=31536000, immutable",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

async function deleteStoredMedia(env, url) {
  const match = String(url || "").match(/^\/media\/([a-f0-9]{32})$/i);
  if (!match) return;

  try {
    await ensureMediaTable(env);
    await env.DB.prepare("DELETE FROM media_files WHERE id = ?").bind(match[1]).run();
  } catch (error) {
    console.error("Falha ao remover mídia antiga:", error);
  }
}

function imagePreview(url, alt = "Imagem atual", banner = false) {
  const src = safeUrl(url);
  if (!src) {
    return `<div class="media-preview empty">Nenhuma imagem cadastrada.</div>`;
  }

  return `
    <div class="media-preview ${banner ? "banner" : ""}">
      <img src="${escapeHtml(src)}" alt="${escapeHtml(alt)}">
    </div>
  `;
}

function adminUploadScript() {
  return String.raw`
(() => {
  const MAX_SERVER_BYTES = 1450000;
  const TARGET_BYTES = 1150000;
  const MAX_DIMENSION = 1800;

  const toBlob = (canvas, type, quality) => new Promise((resolve) => {
    canvas.toBlob(resolve, type, quality);
  });

  async function compressImage(file) {
    if (!file || !file.type.startsWith("image/")) return file;
    if (file.type === "image/svg+xml" || file.type === "image/gif" || file.type === "image/avif") {
      return file;
    }
    if (file.size <= TARGET_BYTES) return file;

    const bitmap = await createImageBitmap(file);
    const scale = Math.min(1, MAX_DIMENSION / Math.max(bitmap.width, bitmap.height));
    const width = Math.max(1, Math.round(bitmap.width * scale));
    const height = Math.max(1, Math.round(bitmap.height * scale));
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext("2d", { alpha: true });
    ctx.drawImage(bitmap, 0, 0, width, height);
    if (bitmap.close) bitmap.close();

    let quality = 0.86;
    let blob = await toBlob(canvas, "image/webp", quality);
    while (blob && blob.size > TARGET_BYTES && quality > 0.5) {
      quality -= 0.1;
      blob = await toBlob(canvas, "image/webp", quality);
    }

    if (!blob) return file;
    const baseName = (file.name || "imagem").replace(/\.[^.]+$/, "");
    return new File([blob], baseName + ".webp", { type: "image/webp" });
  }

  document.querySelectorAll('input[type="file"][data-image-upload]').forEach((input) => {
    input.addEventListener("change", async () => {
      const form = input.closest("form");
      const status = input.nextElementSibling && input.nextElementSibling.classList?.contains("upload-status") ? input.nextElementSibling : null;
      const original = input.files && input.files[0];
      if (!original) return;

      if (form) {
        form.dataset.processingImage = "1";
        form.querySelectorAll('button[type="submit"]').forEach((button) => button.disabled = true);
      }
      if (status) {
        status.textContent = "Preparando imagem...";
        status.classList.remove("ready", "error");
        status.classList.add("processing");
      }

      try {
        const processed = await compressImage(original);
        if (processed.size > MAX_SERVER_BYTES) {
          throw new Error("A imagem ainda ficou grande demais. Escolha outra com menos detalhes ou menor resolução.");
        }

        if (processed !== original) {
          const transfer = new DataTransfer();
          transfer.items.add(processed);
          input.files = transfer.files;
        }

        if (status) {
          const kb = Math.max(1, Math.round(processed.size / 1024));
          status.textContent = "Imagem pronta para enviar (" + kb + " KB).";
          status.classList.remove("processing", "error");
          status.classList.add("ready");
        }
      } catch (error) {
        input.value = "";
        if (status) {
          status.textContent = error?.message || "Não foi possível preparar a imagem.";
          status.classList.remove("processing", "ready");
          status.classList.add("error");
        }
      } finally {
        if (form) {
          delete form.dataset.processingImage;
          form.querySelectorAll('button[type="submit"]').forEach((button) => button.disabled = false);
        }
      }
    });
  });

  document.querySelectorAll("form.image-upload-form").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (form.dataset.processingImage === "1") {
        event.preventDefault();
        alert("Aguarde a imagem terminar de ser preparada antes de salvar.");
      }
    });
  });
})();
`;
}

/* =========================
   ESTATÍSTICAS DE VISITAS
========================= */

async function ensureVisitTable(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS analytics_daily (
      day TEXT PRIMARY KEY,
      visits INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
}

async function recordVisit(env, request) {
  try {
    const method = String(request.method || "GET").toUpperCase();
    if (method !== "GET" && method !== "HEAD") return;

    const userAgent = String(request.headers.get("User-Agent") || "").toLowerCase();
    if (/bot|crawler|spider|slurp|preview|facebookexternalhit|whatsapp/.test(userAgent)) return;

    await ensureVisitTable(env);
    const day = getBrazilDateKey(new Date());

    await env.DB.prepare(`
      INSERT INTO analytics_daily (day, visits, updated_at)
      VALUES (?, 1, CURRENT_TIMESTAMP)
      ON CONFLICT(day) DO UPDATE SET
        visits = visits + 1,
        updated_at = CURRENT_TIMESTAMP
    `)
      .bind(day)
      .run();
  } catch (error) {
    console.error("Falha ao registrar visita:", error);
  }
}

async function getVisitStats(env) {
  try {
    await ensureVisitTable(env);

    const today = getBrazilDateKey(new Date());
    const start7 = getBrazilDateKey(new Date(Date.now() - 6 * 24 * 60 * 60 * 1000));

    const yesterday = getBrazilDateKey(new Date(Date.now() - 24 * 60 * 60 * 1000));
    const start30 = getBrazilDateKey(new Date(Date.now() - 29 * 24 * 60 * 60 * 1000));

    const [totalRow, todayRow, yesterdayRow, last7Row, last30Row] = await Promise.all([
      env.DB.prepare("SELECT COALESCE(SUM(visits), 0) AS total FROM analytics_daily").first(),
      env.DB.prepare("SELECT COALESCE(visits, 0) AS total FROM analytics_daily WHERE day = ?")
        .bind(today)
        .first(),
      env.DB.prepare("SELECT COALESCE(visits, 0) AS total FROM analytics_daily WHERE day = ?")
        .bind(yesterday)
        .first(),
      env.DB.prepare("SELECT COALESCE(SUM(visits), 0) AS total FROM analytics_daily WHERE day >= ? AND day <= ?")
        .bind(start7, today)
        .first(),
      env.DB.prepare("SELECT COALESCE(SUM(visits), 0) AS total FROM analytics_daily WHERE day >= ? AND day <= ?")
        .bind(start30, today)
        .first(),
    ]);

    return {
      total: Number(totalRow?.total || 0),
      today: Number(todayRow?.total || 0),
      yesterday: Number(yesterdayRow?.total || 0),
      last7: Number(last7Row?.total || 0),
      last30: Number(last30Row?.total || 0),
    };
  } catch (error) {
    console.error("Falha ao carregar estatísticas:", error);
    return { total: 0, today: 0, yesterday: 0, last7: 0, last30: 0 };
  }
}

function getBrazilDateKey(date) {
  const parts = new Intl.DateTimeFormat("pt-BR", {
    timeZone: "America/Sao_Paulo",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(date);

  const values = {};
  for (const part of parts) {
    if (part.type !== "literal") values[part.type] = part.value;
  }

  return `${values.year}-${values.month}-${values.day}`;
}

async function hashPassword(password, salt) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: encoder.encode(salt),
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    256
  );

  return bytesToHex(new Uint8Array(bits));
}

async function sha256(value) {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(digest));
}

function randomHex(bytesLength) {
  const bytes = new Uint8Array(bytesLength);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  for (const item of cookies.split(";")) {
    const [key, ...rest] = item.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}

function redirect(request, path) {
  return Response.redirect(new URL(path, request.url).toString(), 302);
}

function htmlResponse(content, status = 200, allowCache = false) {
  const headers = {
    "Content-Type": "text/html; charset=UTF-8",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
  };

  headers["Cache-Control"] = allowCache ? "public, max-age=60" : "no-store";
  return new Response(content, { status, headers });
}

function normalizePathname(pathname) {
  if (!pathname || pathname === "/") return "/";
  // Aceita também /sitemap.xml/ e /robots.txt/ sem cair na página inicial.
  return pathname.replace(/\/+$/, "") || "/";
}

function textResponse(content, contentType, maxAge = 300) {
  const body = String(content ?? "");
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": contentType,
      "Cache-Control": `public, max-age=${maxAge}`,
      "X-Content-Type-Options": "nosniff",
      "Content-Length": String(new TextEncoder().encode(body).byteLength),
    },
  });
}

function successBox(message) {
  return `<div class="saved-message">✓ ${escapeHtml(message)}</div>`;
}

function errorBox(message) {
  return `<div class="error-message">${escapeHtml(message)}</div>`;
}

function safeUrl(value) {
  const text = String(value || "").trim();
  if (!text) return "";
  if (/^\/media\/[a-f0-9]{32}$/i.test(text)) return text;
  try {
    const url = new URL(text);
    if (url.protocol === "https:" || url.protocol === "http:") return url.toString();
  } catch (_) {}
  return "";
}

function escapeCssUrl(value) {
  return String(value || "").replace(/["'()\\]/g, "");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeXml(value) {
  return escapeHtml(value);
}

function notFoundPage() {
  return authLayout(
    "Página não encontrada",
    `
      <h1>GLOBAL <span>PLAY</span></h1>
      <h2>Página não encontrada</h2>
      <p>O endereço solicitado não existe.</p>
      <a class="button" href="/">VOLTAR AO SITE</a>
    `
  );
}

function errorPage(message) {
  return authLayout(
    "Erro",
    `
      <h1>GLOBAL <span>PLAY</span></h1>
      <h2>Ocorreu um erro</h2>
      ${errorBox(message)}
      <a class="button" href="/admin">VOLTAR AO PAINEL</a>
    `
  );
}
