import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const authClient = createClient(supabaseUrl, anonKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});

const adminClient = createClient(supabaseUrl, serviceRoleKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});

function json(body: Record<string, unknown>, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: corsHeaders,
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ ok: false, message: "Method not allowed." }, 405);

  try {
    const authHeader = req.headers.get("Authorization") || "";
    const token = authHeader.replace(/^Bearer\s+/i, "").trim();
    if (!token) return json({ ok: false, message: "Chưa đăng nhập." }, 401);

    const { data: userData, error: userError } = await authClient.auth.getUser(token);
    const caller = userData?.user;
    if (userError || !caller) return json({ ok: false, message: "Phiên đăng nhập không hợp lệ." }, 401);

    const { data: profile, error: profileError } = await adminClient
      .from("profiles")
      .select("role")
      .eq("id", caller.id)
      .maybeSingle();

    if (profileError || profile?.role !== "admin") {
      return json({ ok: false, message: "Bạn không có quyền tạo tài khoản giáo viên." }, 403);
    }

    const body = await req.json();
    const full_name = String(body?.full_name || "").trim();
    const email = String(body?.email || "").trim().toLowerCase();
    const password = String(body?.password || "");

    if (!full_name || !email || !password) {
      return json({ ok: false, message: "Vui lòng nhập đầy đủ họ tên, email và mật khẩu." }, 400);
    }
    if (password.length < 6) {
      return json({ ok: false, message: "Mật khẩu phải có ít nhất 6 ký tự." }, 400);
    }

    const { data: created, error: createError } = await adminClient.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { full_name },
    });

    if (createError) {
      return json({ ok: false, message: createError.message }, 400);
    }

    return json({
      ok: true,
      message: "Tạo tài khoản giáo viên thành công.",
      user: { id: created.user?.id, email: created.user?.email },
    });
  } catch (error) {
    console.error(error);
    return json({ ok: false, message: "Lỗi máy chủ khi tạo tài khoản." }, 500);
  }
});
