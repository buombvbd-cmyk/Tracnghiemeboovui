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
  return new Response(JSON.stringify(body), { status, headers: corsHeaders });
}

async function requireAdmin(req: Request) {
  const authHeader = req.headers.get("Authorization") || "";
  const token = authHeader.replace(/^Bearer\s+/i, "").trim();
  if (!token) throw new Error("UNAUTH:Chưa đăng nhập.");

  const { data, error } = await authClient.auth.getUser(token);
  if (error || !data?.user) throw new Error("UNAUTH:Phiên đăng nhập không hợp lệ.");

  const { data: profile, error: profileError } = await adminClient
    .from("profiles").select("role").eq("id", data.user.id).maybeSingle();

  if (profileError || profile?.role !== "admin") throw new Error("FORBIDDEN:Bạn không có quyền quản trị.");
  return data.user;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ ok: false, message: "Method not allowed." }, 405);

  try {
    const caller = await requireAdmin(req);
    const body = await req.json();
    const action = String(body?.action || "list").trim();

    if (action === "list") {
      const { data: profiles, error: profileError } = await adminClient
        .from("profiles")
        .select("id,full_name,role,created_at")
        .order("created_at", { ascending: false });
      if (profileError) return json({ ok: false, message: profileError.message }, 400);

      const { data: usersData, error: usersError } = await adminClient.auth.admin.listUsers({ page: 1, perPage: 1000 });
      if (usersError) return json({ ok: false, message: usersError.message }, 400);

      const users = usersData?.users || [];
      const rows = (profiles || []).map((p) => {
        const u = users.find((x) => x.id === p.id);
        const bannedUntil = u?.banned_until || null;
        const isBanned = !!bannedUntil && new Date(bannedUntil).getTime() > Date.now();
        return {
          id: p.id,
          full_name: p.full_name || "",
          email: u?.email || "",
          role: p.role || "teacher",
          created_at: p.created_at,
          last_sign_in_at: u?.last_sign_in_at || null,
          banned_until: bannedUntil,
          active: !isBanned,
        };
      });
      return json({ ok: true, users: rows });
    }

    const userId = String(body?.user_id || "").trim();
    if (!userId) return json({ ok: false, message: "Thiếu user_id." }, 400);
    if (userId === caller.id && ["toggle","delete","reset"].includes(action)) {
      return json({ ok: false, message: "Không thể khóa, xóa hoặc đổi mật khẩu chính tài khoản ADMIN đang đăng nhập." }, 400);
    }

    const { data: targetProfile } = await adminClient
      .from("profiles").select("id,role").eq("id", userId).maybeSingle();
    if (!targetProfile) return json({ ok: false, message: "Không tìm thấy tài khoản." }, 404);

    if (action === "toggle") {
      if (targetProfile.role === "admin") return json({ ok: false, message: "Không thể khóa tài khoản ADMIN." }, 400);
      const active = body?.active === true;
      const { error } = await adminClient.auth.admin.updateUserById(userId, {
        ban_duration: active ? "none" : "876000h",
      });
      if (error) return json({ ok: false, message: error.message }, 400);
      return json({ ok: true, message: active ? "Đã mở khóa tài khoản." : "Đã khóa tài khoản." });
    }

    if (action === "reset") {
      if (targetProfile.role === "admin") return json({ ok: false, message: "Không đổi mật khẩu ADMIN bằng màn hình này." }, 400);
      const password = String(body?.password || "");
      if (password.length < 6) return json({ ok: false, message: "Mật khẩu mới phải có ít nhất 6 ký tự." }, 400);
      const { error } = await adminClient.auth.admin.updateUserById(userId, { password });
      if (error) return json({ ok: false, message: error.message }, 400);
      return json({ ok: true, message: "Đã đổi mật khẩu." });
    }

    if (action === "update_name") {
      const fullName = String(body?.full_name || "").trim();
      if (!fullName) return json({ ok: false, message: "Họ tên không được để trống." }, 400);
      const { error: pError } = await adminClient.from("profiles").update({ full_name: fullName }).eq("id", userId);
      if (pError) return json({ ok: false, message: pError.message }, 400);
      const { error: uError } = await adminClient.auth.admin.updateUserById(userId, { user_metadata: { full_name: fullName } });
      if (uError) return json({ ok: false, message: uError.message }, 400);
      return json({ ok: true, message: "Đã cập nhật họ tên." });
    }

    if (action === "delete") {
      if (targetProfile.role === "admin") return json({ ok: false, message: "Không thể xóa tài khoản ADMIN." }, 400);
      const { error } = await adminClient.auth.admin.deleteUser(userId);
      if (error) return json({ ok: false, message: error.message }, 400);
      return json({ ok: true, message: "Đã xóa tài khoản." });
    }

    return json({ ok: false, message: "Thao tác không hợp lệ." }, 400);
  } catch (error) {
    const message = String(error?.message || error);
    if (message.startsWith("UNAUTH:")) return json({ ok: false, message: message.slice(7) }, 401);
    if (message.startsWith("FORBIDDEN:")) return json({ ok: false, message: message.slice(10) }, 403);
    console.error(error);
    return json({ ok: false, message: "Lỗi máy chủ." }, 500);
  }
});
