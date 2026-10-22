import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "Jingwei",
  version: packageJson.version,
  copyright: `© ${currentYear}, Jingwei (精卫).`,
  meta: {
    title: "Jingwei（精卫）— 自主渗透测试控制台",
    description: "LLM 驱动的全链自动化红队渗透平台",
  },
};
