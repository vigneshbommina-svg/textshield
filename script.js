
"use strict";

// ============================================
// TEXTSHIELD - RULE-BASED MESSAGE ANALYZER
// Five feature bits produce 2^5 = 32 DFA states.
// ============================================

const FEATURES = [
  {
    code: "U",
    name: "Urgency",
    bit: 1,
    colorClass: "feature-u",
    description: "Urgent or threatening language",
    regex: /\b(?:urgent|immediately|act now|account (?:is )?(?:blocked|suspended)|verify now|expires today|final warning|within 24 hours)\b/i
  },
  {
    code: "C",
    name: "Credentials",
    bit: 2,
    colorClass: "feature-c",
    description: "Password or account credentials",
    regex: /\b(?:password|passcode|login credentials|one[- ]time password|otp|pin number|bank details|credit card details)\b/i
  },
  {
    code: "A",
    name: "Suspicious action",
    bit: 4,
    colorClass: "feature-a",
    description: "A request to click, verify, claim, or confirm",
    regex: /\b(?:click here|verify your account|claim your prize|claim your reward|reset your password|confirm your identity|update your details|open the attachment)\b/i
  },
  {
    code: "L",
    name: "URL detected",
    bit: 8,
    colorClass: "feature-l",
    description: "A web link was detected",
    regex: /(?:https?:\/\/|www\.)[^\s<>"']+/i
  },
  {
    code: "P",
    name: "Promotional language",
    bit: 16,
    colorClass: "feature-p",
    description: "Prize, reward, or promotional language",
    regex: /\b(?:congratulations|you have won|free prize|winner|cash reward|limited offer|free gift|exclusive deal|claim your reward)\b/i
  }
];

// Each feature has a unique power-of-two bit.
// Displayed bits are ordered P-L-A-C-U.
// q0 = 00000. q31 = 11111.

function stateBits(mask) {
  return mask.toString(2).padStart(5, "0");
}

function stateName(mask) {
  return `q${mask}`;
}

function isAccepting(mask) {
  const hasCredentials = (mask & 2) !== 0;
  const hasUrgency = (mask & 1) !== 0;
  const hasAction = (mask & 4) !== 0;
  const hasURL = (mask & 8) !== 0;

  return hasCredentials && (hasUrgency || hasAction || hasURL);
}

// Complete DFA transition function.
// Every state has a transition for every feature.
function delta(mask, feature) {
  return mask | feature.bit;
}

// Check that all 32 states and 5 transitions per state exist.
function verifyDFA() {
  let transitionCount = 0;

  for (let state = 0; state < 32; state++) {
    for (const feature of FEATURES) {
      const next = delta(state, feature);

      if (next < 0 || next > 31) {
        throw new Error("Invalid DFA transition.");
      }

      transitionCount++;
    }
  }

  return transitionCount === 160;
}

const elements = {
  input: document.getElementById("messageInput"),
  charCount: document.getElementById("charCount"),
  analyzeBtn: document.getElementById("analyzeBtn"),
  clearBtn: document.getElementById("clearBtn"),
  resultBadge: document.getElementById("resultBadge"),
  resultEmpty: document.getElementById("resultEmpty"),
  resultContent: document.getElementById("resultContent"),
  resultBanner: document.getElementById("resultBanner"),
  resultSymbol: document.getElementById("resultSymbol"),
  resultTitle: document.getElementById("resultTitle"),
  resultSummary: document.getElementById("resultSummary"),
  finalState: document.getElementById("finalState"),
  finalBits: document.getElementById("finalBits"),
  featureCount: document.getElementById("featureCount"),
  featureList: document.getElementById("featureList"),
  explanationList: document.getElementById("explanationList"),
  simState: document.getElementById("simState"),
  simResult: document.getElementById("simResult"),
  pathHint: document.getElementById("pathHint"),
  transitionPath: document.getElementById("transitionPath"),
  transitionTableBody: document.getElementById("transitionTableBody"),
  historyList: document.getElementById("historyList"),
  clearHistoryBtn: document.getElementById("clearHistoryBtn"),
  toast: document.getElementById("toast")
};

let history = [];
let toastTimer = null;

const SAMPLES = {
  phishing:
    "URGENT! Your account is blocked. Click here to verify your password immediately: https://example.com",
  spam:
    "Congratulations! You have won a free prize and cash reward. Limited offer!",
  normal:
    "Hello everyone, our computer science class will begin at 10 AM tomorrow in the laboratory.",
  link:
    "Visit https://example.com for the college timetable."
};

const RESULT_INFO = {
  phishing: {
    title: "Possible Phishing",
    badge: "POSSIBLE PHISHING",
    tone: "danger",
    symbol: "⚠",
    summary: "The credential feature and at least one additional phishing-related feature were detected."
  },
  spam: {
    title: "Possible Spam",
    badge: "POSSIBLE SPAM",
    tone: "warning",
    symbol: "!",
    summary: "Promotional language was detected, but the phishing accepting condition was not satisfied."
  },
  suspicious: {
    title: "Suspicious Patterns Found",
    badge: "PATTERNS FOUND",
    tone: "info",
    symbol: "⌕",
    summary: "One or more tracked features were found, but the phishing accepting condition was not satisfied."
  },
  normal: {
    title: "No Known Warning Pattern",
    badge: "NO MATCH",
    tone: "success",
    symbol: "✓",
    summary: "None of the five predefined feature patterns was detected."
  }
};

function detectFeatures(message) {
  return FEATURES.map(feature => {
    const match = message.match(feature.regex);

    return {
      ...feature,
      found: Boolean(match),
      matchedText: match ? match[0] : ""
    };
  });
}

function classify(mask) {
  if (isAccepting(mask)) {
    return "phishing";
  }

  if ((mask & 16) !== 0) {
    return "spam";
  }

  if (mask !== 0) {
    return "suspicious";
  }

  return "normal";
}

function analyzeMessage(message) {
  const detected = detectFeatures(message);
  const matched = detected.filter(feature => feature.found);

  // The feature extractor creates one symbol for each matched
  // feature type, in a fixed order: U, C, A, L, P.
  // The DFA then processes that feature sequence.
  let currentMask = 0;

  const path = [{
    mask: 0,
    input: "START",
    from: null,
    calculation: "Initial state",
    to: 0
  }];

  const transitions = [];

  for (const feature of matched) {
    const from = currentMask;
    const to = delta(from, feature);
    const calculation =
      `${stateBits(from)} OR ${stateBits(feature.bit)} = ${stateBits(to)}`;

    transitions.push({
      from,
      input: feature.code,
      featureName: feature.name,
      featureBit: feature.bit,
      calculation,
      to
    });

    currentMask = to;

    path.push({
      mask: currentMask,
      input: feature.code,
      from,
      calculation,
      to: currentMask
    });
  }

  return {
    message,
    detected,
    matched,
    mask: currentMask,
    bits: stateBits(currentMask),
    path,
    transitions,
    classification: classify(currentMask),
    accepting: isAccepting(currentMask)
  };
}

function addText(parent, tag, text, className) {
  const element = document.createElement(tag);

  if (className) {
    element.className = className;
  }

  element.textContent = text;
  parent.appendChild(element);

  return element;
}

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.add("show");

  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    elements.toast.classList.remove("show");
  }, 2600);
}

function setResultBadge(result) {
  elements.resultBadge.className = `result-badge ${result.tone}`;
  elements.resultBadge.textContent = result.badge;
}

function renderFeatureList(analysis) {
  elements.featureList.replaceChildren();

  for (const feature of analysis.detected) {
    const card = document.createElement("div");

    card.className =
      `feature-item ${feature.colorClass}` +
      (feature.found ? "" : " not-found");

    const letter = addText(
      card,
      "span",
      feature.code,
      "feature-letter"
    );

    letter.setAttribute("aria-hidden", "true");

    const details = document.createElement("div");

    addText(details, "strong", feature.name);
    addText(
      details,
      "small",
      feature.found
        ? `Matched: "${feature.matchedText}"`
        : "Not detected"
    );

    card.appendChild(details);
    elements.featureList.appendChild(card);
  }
}

function buildExplanations(analysis) {
  const messages = [];

  if (analysis.matched.length === 0) {
    messages.push(
      "No feature regular expression matched this message."
    );
  }

  for (const feature of analysis.matched) {
    messages.push(
      `${feature.code} (${feature.name}) was detected from "${feature.matchedText}".`
    );
  }

  if (analysis.accepting) {
    messages.push(
      "The accepting condition is satisfied: C AND (U OR A OR L)."
    );
  } else {
    messages.push(
      "The accepting condition is not satisfied because credentials are absent, or credentials were not combined with urgency, a suspicious action, or a URL."
    );
  }

  if (
    analysis.classification === "spam"
  ) {
    messages.push(
      "The extra output rule selects Possible Spam because P is present and the phishing rule is not satisfied."
    );
  } else if (
    analysis.classification === "suspicious"
  ) {
    messages.push(
      "The extra output rule selects Suspicious Patterns Found because at least one feature was detected."
    );
  } else if (
    analysis.classification === "normal"
  ) {
    messages.push(
      "The extra output rule selects No Known Warning Pattern because the final state is q0."
    );
  }

  messages.push(
    "This is a rule-based educational result, not a guarantee that the message is safe or malicious."
  );

  return messages;
}

function renderResult(analysis) {
  const result = RESULT_INFO[analysis.classification];

  elements.resultEmpty.hidden = true;
  elements.resultContent.hidden = false;

  setResultBadge(result);

  elements.resultBanner.className = `result-banner tone-${result.tone}`;
  elements.resultSymbol.textContent = result.symbol;
  elements.resultTitle.textContent = result.title;
  elements.resultSummary.textContent = result.summary;

  elements.finalState.textContent = stateName(analysis.mask);
  elements.finalBits.textContent = analysis.bits;
  elements.featureCount.textContent =
    `${analysis.matched.length} / ${FEATURES.length}`;

  renderFeatureList(analysis);

  elements.explanationList.replaceChildren();

  for (const explanation of buildExplanations(analysis)) {
    addText(elements.explanationList, "li", explanation);
  }
}

function renderPath(analysis) {
  elements.transitionPath.replaceChildren();

  elements.pathHint.textContent = analysis.matched.length
    ? "Features are processed in the fixed order U → C → A → L → P, skipping unmatched features."
    : "No feature was matched. The DFA remains in its initial state q0.";

  for (let i = 0; i < analysis.path.length; i++) {
    const step = analysis.path[i];
    const isFinal = i === analysis.path.length - 1;
    const node = document.createElement("div");

    node.className = "path-node";

    if (isFinal) {
      node.classList.add("active-node");
    }

    if (isFinal && analysis.accepting) {
      node.classList.add("accept-node");
    }

    addText(node, "strong", stateName(step.mask));
    addText(node, "span", stateBits(step.mask));

    addText(
      node,
      "small",
      i === 0
        ? "START"
        : (isFinal && analysis.accepting
            ? "ACCEPTING"
            : step.input)
    );

    elements.transitionPath.appendChild(node);

    if (i < analysis.path.length - 1) {
      const transition = analysis.transitions[i];
      const arrow = document.createElement("div");

      arrow.className = "path-arrow";
      addText(arrow, "span", "→");
      addText(arrow, "small", transition.input);

      elements.transitionPath.appendChild(arrow);
    }
  }

  elements.simState.textContent =
    `${stateName(analysis.mask)} · ${analysis.bits}`;

  elements.simResult.textContent = analysis.accepting
    ? "Accepting"
    : "Non-accepting";
}

function renderTransitionTable(analysis) {
  elements.transitionTableBody.replaceChildren();

  if (analysis.transitions.length === 0) {
    const row = document.createElement("tr");
    const cell = addText(
      row,
      "td",
      "No feature transitions. The DFA stays at q0.",
      "table-empty"
    );

    cell.colSpan = 4;
    elements.transitionTableBody.appendChild(row);
    return;
  }

  for (const transition of analysis.transitions) {
    const row = document.createElement("tr");

    addText(row, "td", stateName(transition.from));
    addText(
      row,
      "td",
      `${transition.input} — ${transition.featureName}`
    );
    addText(row, "td", transition.calculation);
    addText(row, "td", stateName(transition.to));

    elements.transitionTableBody.appendChild(row);
  }
}

function renderHistory() {
  elements.historyList.replaceChildren();

  if (history.length === 0) {
    addText(
      elements.historyList,
      "p",
      "No messages analyzed yet.",
      "muted"
    );
    return;
  }

  for (const entry of history) {
    const row = document.createElement("div");
    row.className = "history-item";

    const details = document.createElement("div");
    details.className = "history-message";

    addText(details, "strong", entry.preview);
    addText(
      details,
      "small",
      `${entry.state} · ${entry.bits} · ${entry.time}`
    );

    const result = RESULT_INFO[entry.classification];
    const badge = addText(
      row,
      "span",
      result.title,
      `history-label ${result.tone}`
    );

    row.appendChild(details);
    row.appendChild(badge);
    elements.historyList.appendChild(row);
  }
}

function runAnalysis() {
  const message = elements.input.value.trim();

  if (!message) {
    showToast("Please enter a message or choose a sample.");
    elements.input.focus();
    return;
  }

  const analysis = analyzeMessage(message);

  renderResult(analysis);
  renderPath(analysis);
  renderTransitionTable(analysis);

  history.unshift({
    preview: message.length > 75
      ? `${message.slice(0, 72)}...`
      : message,
    state: stateName(analysis.mask),
    bits: analysis.bits,
    classification: analysis.classification,
    time: new Date().toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit"
    })
  });

  // Keep only the latest 8 entries in this page session.
  history = history.slice(0, 8);
  renderHistory();

  showToast(`Analysis complete: ${RESULT_INFO[analysis.classification].title}`);
}

function resetResults() {
  elements.resultContent.hidden = true;
  elements.resultEmpty.hidden = false;

  elements.resultBadge.className = "result-badge neutral";
  elements.resultBadge.textContent = "NOT ANALYZED";

  elements.simState.textContent = "q0 · 00000";
  elements.simResult.textContent = "Not evaluated";
  elements.pathHint.textContent =
    "Analyze a message to populate its DFA path.";

  elements.transitionPath.replaceChildren();

  const startNode = document.createElement("div");
  startNode.className = "path-node active-node";

  addText(startNode, "strong", "q0");
  addText(startNode, "span", "00000");
  addText(startNode, "small", "START");

  elements.transitionPath.appendChild(startNode);

  elements.transitionTableBody.replaceChildren();

  const row = document.createElement("tr");
  const cell = addText(
    row,
    "td",
    "Transitions will appear here after analysis.",
    "table-empty"
  );

  cell.colSpan = 4;
  elements.transitionTableBody.appendChild(row);
}

function clearAll() {
  elements.input.value = "";
  elements.charCount.textContent = "0 / 5000 characters";

  resetResults();
  elements.input.focus();

  showToast("Message and results cleared. History is unchanged.");
}

elements.input.addEventListener("input", () => {
  elements.charCount.textContent =
    `${elements.input.value.length} / 5000 characters`;
});

elements.analyzeBtn.addEventListener("click", runAnalysis);
elements.clearBtn.addEventListener("click", clearAll);

document.querySelectorAll("[data-sample]").forEach(button => {
  button.addEventListener("click", () => {
    const sampleName = button.dataset.sample;

    elements.input.value = SAMPLES[sampleName] || "";
    elements.charCount.textContent =
      `${elements.input.value.length} / 5000 characters`;

    elements.input.focus();
    showToast("Sample loaded. Select Analyze Message.");
  });
});

elements.clearHistoryBtn.addEventListener("click", () => {
  history = [];
  renderHistory();
  showToast("Analysis history cleared.");
});

// Verify the transition function is complete.
if (!verifyDFA()) {
  elements.simResult.textContent = "DFA verification failed";
  elements.analyzeBtn.disabled = true;
  showToast("There is a problem with the DFA transition model.");
}

const runDFAButton = document.getElementById("runDFAButton");

if (runDFAButton) {
  runDFAButton.addEventListener("click", showInteractiveDFA);
}

function showInteractiveDFA() {
  const inputBox = document.querySelector("textarea");
  const graph = document.getElementById("dfaGraph");
  const pathOutput = document.getElementById("dfaPath");
  const stateOutput = document.getElementById("dfaCurrentState");
  const meaningOutput = document.getElementById("dfaStateMeaning");

  if (!inputBox || !graph) return;

  const message = inputBox.value.trim();

  if (!message) {
    graph.innerHTML = "<p>Please enter a message first.</p>";
    pathOutput.textContent = "No transitions yet.";
    stateOutput.textContent = "Current state: q0";
    meaningOutput.textContent = "Enter a message to begin.";
    return;
  }

  // Detect each feature using the project's existing regular expressions.
  const detectedFeatures = FEATURES.filter(feature =>
    feature.regex.test(message)
  );

  // The DFA processes the features in the same fixed order as the project.
  let mask = 0;
  const states = [{ mask: 0, label: "START" }];

  detectedFeatures.forEach(feature => {
    mask = delta(mask, feature);
    states.push({ mask, label: feature.code });
  });

  graph.innerHTML = "";

  states.forEach((state, index) => {
    const node = document.createElement("div");
    node.className = "dfa-node";

    if (index === 0) node.classList.add("initial");
    if (index === states.length - 1) node.classList.add("active");
    if (isAccepting(state.mask)) node.classList.add("accepting");

    const stateName = document.createElement("strong");
    stateName.textContent = `q${state.mask}`;

    const stateBits = document.createElement("small");
    stateBits.textContent = state.mask.toString(2).padStart(5, "0");

    node.append(stateName, stateBits);
    graph.appendChild(node);

    if (index < states.length - 1) {
      const arrow = document.createElement("div");
      arrow.className = "dfa-arrow";

      const symbol = document.createElement("small");
      symbol.textContent = states[index + 1].label;

      const arrowText = document.createElement("span");
      arrowText.textContent = "→";

      arrow.append(symbol, arrowText);
      graph.appendChild(arrow);
    }
  });

  const statePath = states.map(state => `q${state.mask}`).join(" → ");
  const accepting = isAccepting(mask);

  pathOutput.textContent = `Path: ${statePath}`;
  stateOutput.textContent =
    `Current state: q${mask} (${mask.toString(2).padStart(5, "0")})`;

  if (accepting) {
    meaningOutput.textContent =
      "Accepting state: the message contains credential-related language together with urgency, a suspicious action, or a URL.";
  } else {
    meaningOutput.textContent =
      "Non-accepting state: the DFA's phishing acceptance condition is not satisfied. This does not guarantee that the message is safe.";
  }

  if (detectedFeatures.length === 0) {
    meaningOutput.textContent =
      "No configured warning features were detected. The DFA remains in q0.";
  }
}
