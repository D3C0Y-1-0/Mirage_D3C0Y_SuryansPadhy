// The ONE place to change project links and credits. Used by the landing page and the app.
// Replace the GitHub placeholder with your repository URL, e.g. "https://github.com/your-name/cascade".
window.CASCADE_SITE = {
  github: "[ADD_GITHUB_REPOSITORY_URL]",
  project: "Cascade",
  title: "Critical Infrastructure Cyber-Risk Intelligence Platform",
  problem: "PS03: AI-Based Critical Infrastructure Cyber-Risk Prediction",
  team: [
    { name: "Dhruv Salunkhe", role: "Backend, simulation engine, digital twin and platform UI" },
    { name: "Suryans Padhy", role: "Master dataset (SENTINEL city), vulnerability intelligence and the water anomaly detection ML (BATADAL, Model C)" },
  ],
};
window.cascadeGithubReady = () => /^https?:\/\//.test(window.CASCADE_SITE.github);
