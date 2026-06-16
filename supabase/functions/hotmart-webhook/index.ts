// ============================================================
//  Webhook Hotmart  ->  Supabase
//  Produto principal  → cria usuário + envia link de criar senha
//  Dicionário (order bump, ID 7942993) → libera has_dict no metadata
//  Reembolso do principal → bloqueia acesso (~100 anos)
//  Reembolso do dicionário → revoga has_dict
//
//  Deploy:  supabase functions deploy hotmart-webhook --no-verify-jwt
// ============================================================

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL  = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE  = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const HOTTOK        = Deno.env.get("HOTMART_HOTTOK")!;
const SITE_URL      = Deno.env.get("SITE_URL")!;

const DICT_PRODUCT_ID = "7942993";

const admin = createClient(SUPABASE_URL, SERVICE_ROLE, {
  auth: { autoRefreshToken: false, persistSession: false },
});

const APPROVED = ["PURCHASE_APPROVED", "PURCHASE_COMPLETE", "APPROVED", "COMPLETE"];
const REVOKED  = ["PURCHASE_REFUNDED", "PURCHASE_CHARGEBACK", "PURCHASE_PROTEST", "REFUNDED", "CHARGEBACK", "CANCELLED"];

Deno.serve(async (req) => {
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  let body: any;
  try { body = await req.json(); } catch { return json({ error: "JSON inválido" }, 400); }

  // ---- segurança: confere o token do Hotmart ----
  const tok =
    req.headers.get("x-hotmart-hottok") ||
    req.headers.get("hottok") ||
    body?.hottok ||
    new URL(req.url).searchParams.get("hottok");
  if (!HOTTOK || tok !== HOTTOK) return json({ error: "Não autorizado" }, 401);

  // ---- extrai evento, e-mail e produto ----
  const event = body?.event || body?.status || "";
  const email = String(
    body?.data?.buyer?.email ||
    body?.data?.purchase?.buyer?.email ||
    body?.buyer?.email ||
    body?.email || ""
  ).toLowerCase().trim();
  const productId = String(
    body?.data?.product?.id ||
    body?.product?.id || ""
  );

  if (!email) return json({ ok: true, msg: "evento sem e-mail, ignorado" }, 200);

  const isDict = productId === DICT_PRODUCT_ID;

  // ---- COMPRA APROVADA ----
  if (APPROVED.includes(event)) {
    if (isDict) {
      // Order bump do Dicionário: libera has_dict no usuário existente
      const u = await findUser(email);
      if (u) {
        await admin.auth.admin.updateUserById(u.id, {
          user_metadata: { has_dict: true },
        });
      }
      return json({ ok: true, action: "dict_liberado", email }, 200);
    }

    // Produto principal: cria usuário e envia link de criar senha
    const { error: createErr } = await admin.auth.admin.createUser({
      email,
      email_confirm: true,
    });
    if (createErr && !/already.*registered|exists/i.test(createErr.message)) {
      console.error("createUser:", createErr.message);
    }
    const { error: mailErr } = await admin.auth.resetPasswordForEmail(email, { redirectTo: SITE_URL });
    if (mailErr) console.error("resetPasswordForEmail:", mailErr.message);

    return json({ ok: true, action: "acesso_liberado", email }, 200);
  }

  // ---- REEMBOLSO / CHARGEBACK ----
  if (REVOKED.includes(event)) {
    const u = await findUser(email);
    if (u) {
      if (isDict) {
        // Revoga apenas o dicionário
        await admin.auth.admin.updateUserById(u.id, {
          user_metadata: { has_dict: false },
        });
        return json({ ok: true, action: "dict_revogado", email }, 200);
      }
      // Produto principal: bloqueia o acesso completo
      await admin.auth.admin.updateUserById(u.id, { ban_duration: "876000h" });
      return json({ ok: true, action: "acesso_bloqueado", email }, 200);
    }
    return json({ ok: true, action: "usuario_nao_encontrado", email }, 200);
  }

  return json({ ok: true, msg: "evento ignorado", event }, 200);
});

async function findUser(email: string) {
  const { data } = await admin.auth.admin.listUsers({ perPage: 1000 });
  return data?.users?.find((x) => (x.email || "").toLowerCase() === email) ?? null;
}

function json(obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}
