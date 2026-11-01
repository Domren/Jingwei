// 登录凭据只存在于服务器签发的 HttpOnly Cookie 中，JavaScript 无法读取，
// 因此这里不再有 token 的读写接口。当前实例只有一个固定账户，用户信息
// 用于侧栏展示，会话是否有效由 /api/auth/session 判定。
export interface CurrentUser {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar: string;
  role: string;
}

const CURRENT_USER: CurrentUser = {
  id: "1",
  name: "Jingwei",
  username: "jingwei",
  email: "",
  avatar: "",
  role: "operator",
};

export const auth = {
  getCurrentUser(): CurrentUser {
    return CURRENT_USER;
  },

  async logout(): Promise<void> {
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
      });
    } catch {
      // 网络故障时仍然跳转：proxy 会依据仍然存在的 cookie 把请求送回这里，
      // 随后 session 校验失败的 401 会清除 cookie。
    }
  },
};
