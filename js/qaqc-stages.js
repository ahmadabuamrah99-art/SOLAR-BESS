// QA/QC work stages. Each stage is linked to project activities by name (regular expression).
// If an activity is named differently in the project, change its pattern here.
// A stage with no matching activity shows "not linked" in the QA/QC page.
export const QAQC_GROUPS = [
  {
    name: "Mechanical works",
    stages: [
      { key: "ramming", label: "Ramming", match: /piling|ramming/i },
      { key: "structure", label: "Structure", match: /^(?!.*inverter).*structure/i },
      { key: "module", label: "Module", match: /module/i },
      { key: "inv-structure", label: "Inverter structure", match: /inverter.*structure/i },
      { key: "inv-install", label: "Inverter installation", match: /^(?!.*structure).*inverter.*install/i },
    ],
  },
  {
    name: "Electrical works",
    stages: [
      { key: "dc-pull", label: "DC cable pull", match: /dc cable.*(pull|install)|pull.*dc cable/i },
      { key: "dc-term", label: "DC cable termination", match: /termination/i },
    ],
  },
];
