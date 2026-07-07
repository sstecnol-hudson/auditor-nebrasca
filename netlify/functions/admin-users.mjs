import { admin, getUser } from "@netlify/identity";

const json = (body, status = 200) =>
  Response.json(body, {
    status,
    headers: { "Cache-Control": "no-store" },
  });

const isAdmin = (user) => {
  const roles = Array.isArray(user?.roles) ? user.roles : [];
  return user?.role === "admin" || roles.includes("admin");
};

const publicUser = (user) => ({
  id: user.id,
  email: user.email,
  name: user.name,
  role: user.role,
  roles: user.roles || [],
  confirmedAt: user.confirmedAt,
  createdAt: user.createdAt,
  lastSignInAt: user.lastSignInAt,
});

export default async (request) => {
  const currentUser = await getUser();

  if (!currentUser) {
    return json({ error: "Faça login para continuar." }, 401);
  }

  if (!isAdmin(currentUser)) {
    return json({ error: "Acesso permitido apenas para administradores." }, 403);
  }

  if (request.method === "GET") {
    const users = await admin.listUsers({ perPage: 100 });
    return json({ users: users.map(publicUser) });
  }

  if (request.method === "POST") {
    let payload;
    try {
      payload = await request.json();
    } catch {
      return json({ error: "Dados inválidos." }, 400);
    }

    const email = String(payload.email || "").trim().toLowerCase();
    const password = String(payload.password || "");
    const name = String(payload.name || "").trim();
    const role = payload.role === "admin" ? "admin" : "user";

    if (!email || !email.includes("@")) {
      return json({ error: "Informe um e-mail válido." }, 400);
    }

    if (password.length < 8) {
      return json({ error: "A senha precisa ter pelo menos 8 caracteres." }, 400);
    }

    const created = await admin.createUser({
      email,
      password,
      data: {
        role,
        app_metadata: { roles: role === "admin" ? ["admin"] : ["user"] },
        user_metadata: name ? { full_name: name } : {},
      },
    });

    return json({ user: publicUser(created) }, 201);
  }

  return json({ error: "Método não permitido." }, 405);
};

export const config = {
  path: "/api/admin/users",
};
