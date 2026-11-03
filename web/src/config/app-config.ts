import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "Jingwei",
  version: packageJson.version,
  copyright: `© ${currentYear}, Jingwei (精卫).`,
  meta: {
    title: "Jingwei（精卫）— 自主渗透测试控制台",
    description:
      "不配 LLM 也能跑的自动化红队渗透平台：端口探测、Web 指纹、POC 命中与 sqlmap / dalfox 专项验证全程不依赖模型；配置 LLM 后自动规划、深挖与利用闭环。",
  },
};
