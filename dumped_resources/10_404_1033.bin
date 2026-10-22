const stage = document.querySelector("#stage");
const createIconDropdown = socials => {
const socialsToggle = socials.querySelector(".socials-toggle");
const socialsLinks = socials.querySelector(".socials-links");
const socialSurface = socials.querySelector(".socials-surface");
const socialItems = [...socialsLinks.children];
const menuExtension = socialItems.length * 42 + 8;
const expandedHeight = 44 + menuExtension;
const socialSymbol = socialsToggle.querySelector("svg, .flag-window");
// One continuous spring drives the surface, fill, and trailing icons.
// Reversing direction keeps the current position and velocity.
const socialMotion = { value: 0, speed: 0, target: 0, frame: 0, time: 0, entrance: null,
  items: socialItems.map(() => ({ value: 0, speed: 0 })) };
const socialClamp = value => Math.max(0, Math.min(1, value));
const socialEase = value => value * value * (3 - 2 * value);
const stepSocialSpring = (motion, target, dt, frequency, damping = .78) => {
  const displacement = motion.value - target;
  const decay = Math.exp(-damping * frequency * dt);
  const damped = frequency * Math.sqrt(1 - damping * damping);
  const phase = damped * dt;
  const auxiliary = (motion.speed + damping * frequency * displacement) / damped;
  const wave = displacement * Math.cos(phase) + auxiliary * Math.sin(phase);
  motion.value = target + decay * wave;
  motion.speed = decay * (-damping * frequency * wave + damped *
    (-displacement * Math.sin(phase) + auxiliary * Math.cos(phase)));
};
const drawSocials = () => {
  const progress = Math.max(0, socialMotion.value);
  const height = 44 + menuExtension * progress ** 1.65;
  const fill = socialEase(socialClamp(progress / .35));
  socialSurface.style.height = `${height}px`;
  // A slight stretch follows speed, then naturally settles to the final size.
  socialSurface.style.transform = `scaleX(${1 - Math.min(.065, Math.max(-.018, socialMotion.speed * .018))})`;
  // Bloom across the button first, then let the white follow the extending
  // panel. The same curve runs backwards on close, without a color snap.
  socialSurface.style.setProperty("--social-fill", `${31 * fill + height - 44}px`);
  socialsToggle.style.color = `rgb(${Math.round(221 - 204 * fill)} ${Math.round(221 - 204 * fill)} ${Math.round(221 - 204 * fill)})`;
  socialSymbol.style.transform = `rotate(${-socialMotion.speed * 6}deg) scale(${1 - Math.min(.12, Math.abs(socialMotion.speed) * .035)})`;
  socialsLinks.style.visibility = socialMotion.target || progress > .015 ? "visible" : "hidden";
  socialsLinks.style.clipPath = `inset(0 0 ${Math.max(0, expandedHeight - height)}px)`;
  socialItems.forEach((item, index) => {
    const value = socialMotion.items[index].value;
    item.style.opacity = String(socialClamp(value));
    item.style.transform = `translateY(${-24 * (1 - value)}px) scale(${.65 + .35 * value}) rotate(${(index % 2 ? 9 : -9) * (1 - value)}deg)`;
  });
};
const tickSocials = now => {
  const dt = socialMotion.time ? Math.min((now - socialMotion.time) / 1000, .032) : 0;
  socialMotion.time = now;
  if (socialMotion.entrance) {
    socialMotion.entrance.started ??= now;
    const t = socialClamp((now - socialMotion.entrance.started) / 620);
    // A full opening starts at zero speed: the white bloom gets visible
    // screen time before the long panel unfolds. Keep the existing exit.
    socialMotion.value = t ** 3 * (t * (t * 6 - 15) + 10);
    socialMotion.speed = 30 * t * t * (1 - t) ** 2 / .62;
    if (t === 1) socialMotion.entrance = null;
  } else {
    stepSocialSpring(socialMotion, socialMotion.target, dt, socialMotion.target ? 7 : 8);
  }
  const height = 44 + menuExtension * Math.max(0, socialMotion.value) ** 1.65;
  socialMotion.items.forEach((item, index) => {
    const reveal = socialMotion.target ? socialEase(socialClamp((height - (58 + index * 38)) / 30)) : 0;
    stepSocialSpring(item, reveal, dt, socialMotion.target ? 14 : 20, .72);
  });
  const settled = Math.abs(socialMotion.value - socialMotion.target) < .0005 &&
    Math.abs(socialMotion.speed) < .004 && socialMotion.items.every(item =>
      Math.abs(item.value - socialMotion.target) < .001 && Math.abs(item.speed) < .006);
  if (settled) {
    socialMotion.value = socialMotion.target;
    socialMotion.speed = 0;
    socialMotion.items.forEach(item => { item.value = socialMotion.target; item.speed = 0; });
    socialMotion.frame = socialMotion.time = 0;
  }
  drawSocials();
  if (!settled) socialMotion.frame = requestAnimationFrame(tickSocials);
};
const setSocialsOpen = open => {
  if ((socials.dataset.open === "true") === open) return;
  if (open) document.dispatchEvent(new CustomEvent("icon-dropdown-open", { detail: socials }));
  socials.dataset.open = String(open);
  socialsToggle.setAttribute("aria-expanded", String(open));
  socialsLinks.inert = !open;
  socialMotion.entrance = open && Math.abs(socialMotion.value) < .001 &&
    Math.abs(socialMotion.speed) < .004 ? { started: null } : null;
  socialMotion.target = Number(open);
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
    cancelAnimationFrame(socialMotion.frame);
    socialMotion.entrance = null;
    socialMotion.frame = socialMotion.time = socialMotion.speed = 0;
    socialMotion.value = socialMotion.target;
    socialMotion.items.forEach(item => { item.value = socialMotion.target; item.speed = 0; });
    drawSocials();
  } else if (!socialMotion.frame) {
    socialMotion.time = 0;
    socialMotion.frame = requestAnimationFrame(tickSocials);
  }
};
drawSocials();
socialsToggle.addEventListener("click", () => setSocialsOpen(socials.dataset.open !== "true"));
document.addEventListener("pointerdown", event => {
  if (!socials.contains(event.target)) setSocialsOpen(false);
});
document.addEventListener("keydown", event => {
  if (event.key === "Escape" && socials.dataset.open === "true") {
    setSocialsOpen(false);
    socialsToggle.focus();
  }
});
document.addEventListener("icon-dropdown-open", event => {
  if (event.detail !== socials) setSocialsOpen(false);
});
return { toggle: socialsToggle, items: socialItems, setOpen: setSocialsOpen };
};
const socialMenu = createIconDropdown(document.querySelector("#socials"));
const languageMenu = createIconDropdown(document.querySelector("#languages"));
const translations = {
  en: { scan: "scan", scanLabel: "Scan", searching: "Searching for javaw.exe", complete: "Scan complete", found: pid => `Minecraft found (PID ${pid})`, socials: "Socials", language: "Language: English", website: "Website" },
  ru: { scan: "скан", scanLabel: "Сканировать", searching: "Поиск javaw.exe", complete: "Проверка завершена", found: pid => `Minecraft найден (PID ${pid})`, socials: "Соцсети", language: "Язык: Русский", website: "Сайт" },
  lt: { scan: "tikrinti", scanLabel: "Tikrinti", searching: "Ieškoma javaw.exe", complete: "Patikra baigta", found: pid => `Minecraft rastas (PID ${pid})`, socials: "Socialiniai tinklai", language: "Kalba: Lietuvių", website: "Svetainė" },
};
let activeLanguage = "en";
const button = document.querySelector("#start");
const startLabel = document.querySelector(".start-label");
const resultsButton = document.querySelector("#show-results");
const resultsDialog = document.querySelector("#results-dialog");
const nativeHost = window.chrome?.webview;
let nativeScanReady = !nativeHost;
let nativeScanActive = false;
let nativeReturnPending = false;
let nativeScanSucceeded = true;
let nativeProgress = 0;
let nativeCompletedAt = null;
const resultCopy = {
  en: { button: "Show results", title: "Scan results", kind: "Demo scan", note: "No detection data is available in this preview.", close: "Close results" },
  ru: { button: "Результаты", title: "Результаты проверки", kind: "Демо-проверка", note: "В этой демоверсии нет данных об обнаружениях.", close: "Закрыть результаты" },
  lt: { button: "Rezultatai", title: "Patikros rezultatai", kind: "Demonstracinė patikra", note: "Šioje demonstracijoje aptikimo duomenų nėra.", close: "Uždaryti rezultatus" },
};
const revealResults = () => {
  if ((!nativeHost || nativeScanReady) && nativeScanSucceeded) {
    stage.classList.add("has-results");
    resultsButton.disabled = false;
  }
};
resultsButton.addEventListener("click", () => {
  if (resultsButton.disabled || (nativeHost && (!nativeScanReady || !nativeScanSucceeded))) return;
  if (nativeHost) {
    nativeHost.postMessage("results");
    return;
  }
  document.querySelector("#results-process").textContent = translations[activeLanguage].found(demoPid);
  resultsDialog.showModal();
});
resultsDialog.querySelector(".results-close").addEventListener("click", () => resultsDialog.close());
resultsDialog.addEventListener("click", event => {
  if (event.target !== resultsDialog) return;
  const rect = resultsDialog.getBoundingClientRect();
  if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) resultsDialog.close();
});
const rVisual = document.querySelector("#r-visual");
const oLeft = document.querySelector("#o-left");
const oRight = document.querySelector("#o-right");
const tVisual = document.querySelector("#t-visual");
const baselineMarker = document.querySelector("#baseline");
const svg = document.querySelector(".mark");
const rMorph = document.querySelector("#r-morph");
const tMorph = document.querySelector("#t-morph");
const oLeftMorph = document.querySelector("#o-left-morph");
const oRightMorph = document.querySelector("#o-right-morph");
const letterSpin = document.querySelector("#letter-spin");
const oSpin = document.querySelector("#o-spin");
const digitSlots = [...document.querySelectorAll(".digit-slot")];
const scanIsland = document.querySelector("#scan-island");
const islandCopyLayer = document.querySelector("#island-copy-layer");
const islandShape = document.querySelector("#island-shape");
const islandPath = document.querySelector("#island-path");
const islandSearch = document.querySelector("#island-search");
const islandFound = document.querySelector("#island-found");
const scanAnnouncement = document.querySelector("#scan-announcement");
const center = { x: 320, y: 170 };
const pointCount = 180;
const ringPointCount = 256;
const rampTime = 1500;
const mergeTime = 650;
const spinTime = 3400;
const spinSpeed = 360 / spinTime;
const countStepTime = 110;
const completionFadeDelay = 180;
const completionHoldTime = 820;

// Use the same outlines at rest and in motion, avoiding a font-to-path
// handoff that changes the lettering when the scan starts.
// Keep the inner and outer edges separate. Matching each edge to the
// corresponding arc edge prevents the filled shape from folding over
// itself into a pointed wedge halfway through the morph.
const glyphInner = "M32.74 -35.29 Q30.89 -36.74 27.42 -36.74 Q22.90 -36.74 19.86 -32.65 Q16.83 -28.56 16.83 -21.53 V0";
const glyphOuter = "M6.64 0 V-45 H16.83 V-35.73 H17.01 Q18.50 -40.47 21.60 -43.13 Q24.70 -45.79 28.52 -45.79 Q31.29 -45.79 32.74 -44.96";
const tInner = "M19.60 -58.32 V-45 H30.37 V-37 H19.60 V-14.50 Q19.60 -10.50 21.05 -8.79 Q22.50 -7.08 25.88 -7.08 Q28.48 -7.08 30.37 -8.57 V-0.48";
const tOuter = "M30.37 -0.48 Q27.38 1.01 22.50 1.01 Q9.40 1.01 9.40 -11.56 V-37 H1.89 V-45 H9.40 V-55.42 L19.60 -58.32";
const oOuter = "M26.59 1.05 Q16.17 1.05 9.95 -5.25 Q3.74 -11.56 3.74 -21.97 Q3.74 -33.31 10.22 -39.68 Q16.70 -46.05 27.69 -46.05 Q38.23 -46.05 44.12 -39.86 Q50.01 -33.66 50.01 -22.68 Q50.01 -11.91 43.66 -5.43 Q37.31 1.05 26.59 1.05 Z";
const oInner = "M27.07 -37.92 Q21.09 -37.92 17.62 -33.75 Q14.15 -29.58 14.15 -22.24 Q14.15 -15.16 17.67 -11.10 Q21.18 -7.03 27.07 -7.03 Q33.09 -7.03 36.32 -11.03 Q39.55 -15.03 39.55 -22.41 Q39.55 -29.84 36.32 -33.88 Q33.09 -37.92 27.07 -37.92 Z";

const clamp = value => Math.max(0, Math.min(1, value));
const mix = (from, to, amount) => from + (to - from) * amount;
const smoothStep = value => value * value * (3 - 2 * value);
const smootherStep = value => value ** 3 * (value * (value * 6 - 15) + 10);

const sampleEdge = data => {
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", data);
  const length = path.getTotalLength();
  const edgeCount = pointCount / 2;
  return Array.from({ length: edgeCount }, (_, index) => {
    const point = path.getPointAtLength((index / (edgeCount - 1)) * length);
    return [point.x, point.y];
  });
};

const sampleContour = data => {
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", data);
  const length = path.getTotalLength();
  const count = ringPointCount / 2;
  return Array.from({ length: count }, (_, index) => {
    const point = path.getPointAtLength((index / count) * length);
    return [point.x, point.y];
  });
};

const pathFromPoints = points =>
  points.map(([x, y], index) => `${index ? "L" : "M"}${x.toFixed(2)} ${y.toFixed(2)}`).join(" ") + " Z";
const pathFromRing = points =>
  `${pathFromPoints(points.slice(0, ringPointCount / 2))} ${pathFromPoints(points.slice(ringPointCount / 2))}`;

const makeArc = (from, to) => {
  const half = pointCount / 2;
  const outer = Array.from({ length: half }, (_, index) => {
    const angle = mix(from, to, index / (half - 1));
    return [center.x + Math.cos(angle) * 120, center.y + Math.sin(angle) * 120];
  });
  const inner = Array.from({ length: half }, (_, index) => {
    const angle = mix(to, from, index / (half - 1));
    return [center.x + Math.cos(angle) * 117, center.y + Math.sin(angle) * 117];
  });
  // Match the r outline's travel: from the shoulder inward, down the
  // stem, then back around the outside. This avoids a twisted morph.
  return [...inner, ...outer];
};

const rArcPoints = makeArc(Math.PI * 0.76, Math.PI * 1.24);
const tArcPoints = makeArc(Math.PI * 0.24, -Math.PI * 0.24);
const makeRing = (outerRadius, innerRadius) => [
  ...Array.from({ length: ringPointCount / 2 }, (_, index) => {
    const angle = Math.PI / 2 + 2 * Math.PI * index / (ringPointCount / 2);
    const radius = outerRadius(angle);
    return [center.x + Math.cos(angle) * radius, center.y + Math.sin(angle) * radius];
  }),
  ...Array.from({ length: ringPointCount / 2 }, (_, index) => {
    const angle = -Math.PI / 2 - 2 * Math.PI * index / (ringPointCount / 2);
    return [center.x + Math.cos(angle) * innerRadius, center.y + Math.sin(angle) * innerRadius];
  }),
];
const circlePoints = makeRing(() => 41, 35);
const gearPoints = makeRing(angle => {
  const step = Math.PI / 4;
  const offset = (angle - Math.PI / 2) % step;
  const phase = Math.min(offset, step - offset);
  if (phase <= 0.14) return 80;
  if (phase >= 0.26) return 65;
  return mix(80, 65, (phase - 0.14) / 0.12);
}, 40);
let rLetterPoints;
let tLetterPoints;
let oLeftPoints;
let oRightPoints;
let frame;
let isSpinning = false;
let lastOuterAngle = 0;
let lastInnerAngle = 0;
let displayedProgress = -1;
let islandState = "idle";
let demoPid = 0;
let lastClickX = 0;
let lastClickY = 0;
let islandFrame = 0;
let islandLastTime = 0;
let islandTimers = [];
let islandExit = null;
let islandEntrance = null;
const islandMotion = { width: 0, height: 0, widthSpeed: 0, heightSpeed: 0,
  targetWidth: 0, targetHeight: 0 };

// Use a regular rounded rectangle contour: a flat horizontal top, rounded
// corners, and straight sides without the old outward shoulder hooks.
const drawIsland = () => {
  const width = Math.min(Math.max(0, stage.clientWidth - 24), Math.max(0, islandMotion.width));
  const height = Math.max(0, islandMotion.height);

  // Fade only the last few pixels, before rasterization loses the curves.
  scanIsland.style.opacity = String(smoothStep(clamp(Math.min(width / 10, height / 6))));
  const insetX = Math.max(0, (islandCopyLayer.clientWidth - width + 32) / 2);
  islandCopyLayer.style.clipPath = `inset(15px ${insetX}px ${Math.max(15, 50 - height)}px)`;
  // A fixed viewport prevents layout/compositing from resizing the SVG
  // separately from the path on the opening frames.
  const viewportWidth = stage.clientWidth;
  islandShape.setAttribute("viewBox", `0 0 ${viewportWidth} 50`);
  islandPath.setAttribute("transform", `translate(${(viewportWidth - width) / 2} 0)`);
  const r = Math.min(13, width / 2, height);
  islandPath.setAttribute("d", `M${r} 0 H${width-r} Q${width} 0 ${width} ${r} V${height-r} Q${width} ${height} ${width-r} ${height} H${r} Q0 ${height} 0 ${height-r} V${r} Q0 0 ${r} 0 Z`);
};

const springStep = (value, speed, target, dt) => {
  const omega = 15;
  const distance = value - target;
  const auxiliary = speed + omega * distance;
  const decay = Math.exp(-omega * dt);
  return [target + (distance + auxiliary * dt) * decay,
    (speed - omega * auxiliary * dt) * decay];
};

const animateIsland = now => {
  const dt = islandLastTime ? Math.min((now - islandLastTime) / 1000, .05) : .016;
  islandLastTime = now;
  if (islandEntrance) {
    islandEntrance.started ??= now;
    const progress = clamp((now - islandEntrance.started) / 600);
    const amount = smootherStep(progress);
    islandMotion.width = islandMotion.targetWidth * amount;
    islandMotion.height = islandMotion.targetHeight * amount;
    islandMotion.widthSpeed = islandMotion.heightSpeed = 0;
    if (progress === 1) {
      islandEntrance = null;
      islandFrame = 0;
      islandLastTime = 0;
    }
    drawIsland();
    if (islandFrame) islandFrame = requestAnimationFrame(animateIsland);
    return;
  }
  if (islandExit) {
    const progress = clamp((now - islandExit.started) / 440);
    const remaining = 1 - smootherStep(progress);
    islandMotion.width = islandExit.width * remaining;
    // Keep depth longer than width so the closing notch becomes a small
    // rounded shape instead of a shallow strip with imperceptible corners.
    islandMotion.height = islandExit.height * remaining ** .55;
    islandMotion.widthSpeed = islandMotion.heightSpeed = 0;
    if (progress === 1) {
      islandExit = null;
      islandCopyLayer.dataset.message = "idle";
      islandMotion.width = islandMotion.targetWidth = 0;
      islandFrame = 0;
      islandLastTime = 0;
    }
    drawIsland();
    if (islandFrame) islandFrame = requestAnimationFrame(animateIsland);
    return;
  }
  [islandMotion.width, islandMotion.widthSpeed] = springStep(
    islandMotion.width, islandMotion.widthSpeed, islandMotion.targetWidth, dt);
  [islandMotion.height, islandMotion.heightSpeed] = springStep(
    islandMotion.height, islandMotion.heightSpeed, islandMotion.targetHeight, dt);
  if (Math.abs(islandMotion.width - islandMotion.targetWidth) < .15 &&
      Math.abs(islandMotion.height - islandMotion.targetHeight) < .15 &&
      Math.abs(islandMotion.widthSpeed) < .5 &&
      Math.abs(islandMotion.heightSpeed) < .5) {
    islandMotion.width = islandMotion.targetWidth;
    islandMotion.height = islandMotion.targetHeight;
    islandMotion.widthSpeed = islandMotion.heightSpeed = 0;
    islandFrame = 0;
    islandLastTime = 0;

  }
  drawIsland();
  if (islandFrame) islandFrame = requestAnimationFrame(animateIsland);
};

const resizeIsland = (next, animate = true) => {
  // Keep the island inside the clear space between both top-menu controls.
  const available = Math.min(280, Math.max(24, stage.clientWidth - 136));
  const copy = next === "searching" ? islandSearch : islandFound;
  islandMotion.targetWidth = next === "idle" ? 0
    : Math.min(available, Math.ceil(copy.getBoundingClientRect().width + 52));
  islandMotion.targetHeight = next === "idle" ? 0 : 50;
  if (animate && next !== "idle" && islandMotion.height === 0 && !islandEntrance) {
    islandEntrance = { started: null };
  }
  if (animate && !islandFrame) {
    islandLastTime = 0;
    islandFrame = requestAnimationFrame(animateIsland);
  }
};

const setIsland = state => {
  if (state === islandState) return;
  const previousState = islandState;
  islandState = state;
  islandExit = null;
  islandEntrance = null;
  islandTimers.forEach(clearTimeout);
  islandTimers = [];
  const queue = (callback, delay) => {
    islandTimers.push(setTimeout(callback, delay));
  };

  scanAnnouncement.textContent = state === "idle" ? ""
    : (state === "searching" ? islandSearch : islandFound).textContent;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduced) {
    cancelAnimationFrame(islandFrame);
    islandFrame = 0;
    islandCopyLayer.dataset.message = state;
    resizeIsland(state, false);
    islandMotion.width = islandMotion.targetWidth;
    islandMotion.height = islandMotion.targetHeight;
    islandMotion.widthSpeed = islandMotion.heightSpeed = 0;
    drawIsland();
  } else if (state === "searching") {
    islandCopyLayer.dataset.message = "idle";
    resizeIsland(state);
    queue(() => { islandCopyLayer.dataset.message = state; }, 280);
  } else if (state === "found") {
    // Both rows move through one 20px mask on the same timeline.
    resizeIsland(state);
    islandCopyLayer.dataset.message = state;
  } else {
    islandCopyLayer.dataset.message = previousState === "found"
      ? "leaving-found" : "leaving-search";
    queue(() => {
      // Retract to the same top-center anchor used for entry.
      islandMotion.targetHeight = 0;
      islandExit = { started: performance.now(), width: islandMotion.width, height: islandMotion.height };
      if (!islandFrame) islandFrame = requestAnimationFrame(animateIsland);
    }, 160);
  }
};
drawIsland();

const setProgress = (value, instant = false) => {
  if (value === displayedProgress) return;
  displayedProgress = value;
  const digits = [Math.floor(value / 100), Math.floor(value / 10) % 10, value % 10];
  digitSlots.forEach((slot, index) => {
    const visible = index === 2 || value >= Number(slot.dataset.place);
    const next = visible ? String(digits[index]) : "";
    const previous = slot.dataset.value ?? "";
    slot.classList.toggle("is-visible", visible);
    if (next === previous) return;
    const roll = slot.querySelector(".digit-roll");
    const [upper, lower] = roll.children;
    roll.getAnimations().forEach(animation => animation.cancel());
    upper.textContent = previous;
    lower.textContent = next;
    slot.dataset.value = next;
    if (instant || !previous || !next || matchMedia("(prefers-reduced-motion: reduce)").matches) {
      upper.textContent = next;
      lower.textContent = next;
      return;
    }
    const animation = roll.animate([
      { transform: "translateY(0)" },
      { transform: "translateY(-50%)" },
    ], { duration: 105, easing: "cubic-bezier(.2,.65,.25,1)", fill: "forwards" });
    animation.onfinish = () => {
      upper.textContent = next;
      lower.textContent = next;
      animation.cancel();
    };
  });
};

const alignOutline = () => {
  const svgRect = svg.getBoundingClientRect();
  const scale = svgRect.width / 640;
  const baselineY = (baselineMarker.getBoundingClientRect().top - svgRect.top) / scale;
  const placeGlyph = (element, inner, outer) => {
    const startX = (element.getBoundingClientRect().left - svgRect.left) / scale;
    return [...sampleEdge(inner), ...sampleEdge(outer)]
      .map(([x, y]) => [x + startX, y + baselineY]);
  };
  rLetterPoints = placeGlyph(rVisual, glyphInner, glyphOuter);
  tLetterPoints = placeGlyph(tVisual, tInner, tOuter);
  rMorph.setAttribute("d", pathFromPoints(rLetterPoints));
  tMorph.setAttribute("d", pathFromPoints(tLetterPoints));
  const placeRing = element => {
    const startX = (element.getBoundingClientRect().left - svgRect.left) / scale;
    return [...sampleContour(oOuter), ...sampleContour(oInner)]
      .map(([x, y]) => [x + startX, y + baselineY]);
  };
  oLeftPoints = placeRing(oLeft);
  oRightPoints = placeRing(oRight);
  oLeftMorph.setAttribute("d", pathFromRing(oLeftPoints));
  oRightMorph.setAttribute("d", pathFromRing(oRightPoints));
};

const setFrame = (amount, angle, innerAngle = 0, ringAmount = amount, gearAmount = 0) => {
  const morph = (path, letters, arc) => {
    const points = letters.map(([x, y], index) => [
      mix(x, arc[index][0], amount),
      mix(y, arc[index][1], amount),
    ]);
    path.setAttribute("d", pathFromPoints(points));
    path.style.strokeWidth = (5 * amount).toFixed(2);
  };
  morph(rMorph, rLetterPoints, rArcPoints);
  morph(tMorph, tLetterPoints, tArcPoints);
  letterSpin.setAttribute("transform", `rotate(${angle.toFixed(2)} ${center.x} ${center.y})`);
  const morphRing = (path, letters) => {
    const points = letters.map(([x, y], index) => [
      mix(x, mix(circlePoints[index][0], gearPoints[index][0], gearAmount), ringAmount),
      mix(y, mix(circlePoints[index][1], gearPoints[index][1], gearAmount), ringAmount),
    ]);
    path.setAttribute("d", pathFromRing(points));
  };
  morphRing(oLeftMorph, oLeftPoints);
  morphRing(oRightMorph, oRightPoints);
  oSpin.setAttribute("transform", `rotate(${innerAngle.toFixed(2)} ${center.x} ${center.y})`);
  lastOuterAngle = angle;
  lastInnerAngle = innerAngle;
};

const expandButton = () => {
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduced) {
    stage.classList.remove("is-running");
    button.disabled = false;
    revealResults();
    return;
  }
  const stageRect = stage.getBoundingClientRect();
  const buttonRect = button.getBoundingClientRect();
  const homeX = buttonRect.left + buttonRect.width / 2 - stageRect.left;
  const homeY = buttonRect.top + buttonRect.height / 2 - stageRect.top;
  button.style.width = "0px";
  button.style.height = "0px";
  button.style.left = `${lastClickX}px`;
  button.style.top = `${lastClickY}px`;
  startLabel.style.opacity = "0";
  stage.classList.remove("is-running");
  const started = performance.now();
  const expand = now => {
    const progress = clamp((now - started) / 470);
    const amount = smootherStep(progress);
    const width = 40 * amount + 52 * amount ** 3;
    // Move back while the circle is tiny; the fixed label appears after
    // the button has settled at its original position.
    const settle = smoothStep(clamp(amount / .35));
    button.style.width = `${width}px`;
    button.style.height = `${40 * amount}px`;
    button.style.left = `${mix(lastClickX, homeX, settle)}px`;
    button.style.top = `${mix(lastClickY, homeY, settle)}px`;
    startLabel.style.opacity = String(smoothStep(clamp((progress - .72) / .28)));
    if (progress < 1) requestAnimationFrame(expand);
    else {
      button.style.removeProperty("width");
      button.style.removeProperty("height");
      button.style.removeProperty("left");
      button.style.removeProperty("top");
      startLabel.style.removeProperty("opacity");
      button.disabled = false;
      revealResults();
    }
  };
  requestAnimationFrame(expand);
};

const finish = () => {
  if (nativeHost && !nativeScanReady) return;
  nativeScanActive = false;
  isSpinning = false;
  setIsland("idle");
  alignOutline();
  setFrame(0, 0);

  stage.classList.remove("is-loading");
  expandButton();
};

const startReturn = () => {
  cancelAnimationFrame(frame);
  setIsland("idle");
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
    finish();
    return;
  }

  isSpinning = false;
  stage.classList.add("is-running");
  stage.classList.remove("is-loading");
  button.disabled = true;

  const coastTime = 450;
  const morphTime = 850;
  const outerStart = lastOuterAngle;
  const innerStart = lastInnerAngle;
  const coastDistance = spinSpeed * coastTime / 2;
  const outerCoast = outerStart + coastDistance;
  const innerCoast = innerStart - coastDistance;
  const outerEnd = Math.ceil((outerCoast + 0.01) / 360) * 360;
  const angleRemaining = outerEnd - outerCoast;
  const alignTime = 300 + 900 * angleRemaining / 360;
  const morphStart = coastTime + alignTime;
  const totalTime = morphStart + morphTime;
  const started = performance.now();

  const animateReturn = now => {
    const elapsed = Math.min(now - started, totalTime);
    if (elapsed < coastTime) {
      const progress = clamp(elapsed / coastTime);
      // Integrating a smooth deceleration preserves the current spin
      // direction and reaches zero speed without an abrupt freeze.
      const distance = spinSpeed * coastTime *
        (progress - progress ** 3 + 0.5 * progress ** 4);
      setFrame(
        1,
        outerStart + distance,
        innerStart - distance,
        1,
        1 - smootherStep(progress)
      );
    } else if (elapsed < morphStart) {
      const progress = smoothStep(clamp((elapsed - coastTime) / alignTime));
      // The curves keep moving clockwise to their home orientation;
      // the center is already a circle, so it can rest here quietly.
      setFrame(1, mix(outerCoast, outerEnd, progress), innerCoast, 1, 0);
    } else {
      const progress = smootherStep(clamp(
        (elapsed - morphStart) / morphTime
      ));
      // Only after alignment do the stationary arcs bend back into
      // the letters, while the circle separates into the two o's.
      setFrame(1 - progress, outerEnd, 0, 1 - progress, 0);
    }
    if (elapsed < totalTime) frame = requestAnimationFrame(animateReturn);
    else finish();
  };
  frame = requestAnimationFrame(animateReturn);
};

alignOutline();
setFrame(0, 0);
document.fonts.ready.then(() => {
  if (!button.disabled) {
    alignOutline();
    setFrame(0, 0);
  }
});
new ResizeObserver(() => {
  if (!button.disabled) {
    alignOutline();
    setFrame(0, 0);
  }
  if (islandState !== "idle") resizeIsland(islandState);
}).observe(stage);

const beginMorph = () => {
  cancelAnimationFrame(frame);
  if (!nativeHost) demoPid = 1000 + Math.floor(Math.random() * 30000);
  islandFound.textContent = translations[activeLanguage].found(demoPid);
  setIsland("searching");
  alignOutline();
  setFrame(0, 0);

  stage.classList.add("is-running");
  stage.classList.remove("is-loading");
  button.disabled = true;
  setProgress(0, true);

  if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
    setFrame(1, 0, 0, 1, 1);
    stage.classList.add("is-loading");
    const started = performance.now();
    const reducedTick = now => {
      setProgress(nativeHost ? nativeProgress : 100, true);
      const complete = nativeHost
        ? nativeScanReady && nativeCompletedAt !== null && now - nativeCompletedAt >= completionHoldTime
        : now - started >= 600;
      if (complete) { startReturn(); return; }
      frame = requestAnimationFrame(reducedTick);
    };
    frame = requestAnimationFrame(reducedTick);
    return;
  }

  const started = performance.now();
  const animate = now => {
    const elapsed = now - started;
    const progress = clamp(elapsed / rampTime);
    const amount = smoothStep(progress);
    // Integrating a smooth speed ramp gives zero starting speed and
    // reaches the steady turn without a speed jump.
    const rampAngle = spinSpeed * rampTime *
      (progress * progress * progress - 0.5 * progress ** 4);
    const angle = elapsed < rampTime
      ? rampAngle
      : spinSpeed * (elapsed - rampTime / 2);
    const innerAngle = elapsed < mergeTime
      ? 0
      : -spinSpeed * (elapsed - mergeTime);
    const ringAmount = smoothStep(clamp(elapsed / mergeTime));
    const gearAmount = smoothStep(clamp((elapsed - mergeTime) / (rampTime - mergeTime)));
    setFrame(amount, angle % 360, innerAngle % 360, ringAmount, gearAmount);

    if (elapsed >= rampTime) {
      let value;
      if (nativeHost) {
        value = nativeProgress;
        if (nativeScanReady && nativeCompletedAt !== null && now - nativeCompletedAt >= completionFadeDelay) {
          stage.classList.remove("is-loading");
        } else {
          stage.classList.add("is-loading");
        }
      } else {
        const completedAt = rampTime + 100 * countStepTime;
        if (elapsed < completedAt + completionFadeDelay) stage.classList.add("is-loading");
        else stage.classList.remove("is-loading");
        value = Math.min(100, Math.floor((elapsed - rampTime) / countStepTime));
      }
      setProgress(value);
      if (!nativeHost && value >= 55 && islandState === "searching") setIsland("found");
    }

    if (progress === 1 && !isSpinning) {
      isSpinning = true;
    }
    const nativeFinished = nativeHost && progress === 1 && nativeScanReady && nativeCompletedAt !== null && now - nativeCompletedAt >= completionHoldTime;
    const demoFinished = !nativeHost && elapsed >= rampTime + 100 * countStepTime + completionHoldTime;
    if (nativeFinished || demoFinished) {
      startReturn();
      return;
    }
    frame = requestAnimationFrame(animate);
  };
  frame = requestAnimationFrame(animate);
};

button.addEventListener("click", event => {
  if (button.disabled) return;
  nativeScanActive = true;
  nativeScanReady = !nativeHost;
  nativeReturnPending = false;
  nativeScanSucceeded = true;
  nativeProgress = 0;
  nativeCompletedAt = null;
  nativeHost?.postMessage("start");
  const stageRect = stage.getBoundingClientRect();
  const buttonRect = button.getBoundingClientRect();
  const fromX = buttonRect.left + buttonRect.width / 2 - stageRect.left;
  const fromY = buttonRect.top + buttonRect.height / 2 - stageRect.top;
  const toX = event.detail ? event.clientX - stageRect.left : fromX;
  const toY = event.detail ? event.clientY - stageRect.top : fromY;
  lastClickX = toX;
  lastClickY = toY;
  // Preserve the current button position before removing the completed layout.
  button.style.left = `${fromX}px`;
  button.style.top = `${fromY}px`;
  stage.classList.remove("has-results");
  resultsButton.disabled = true;
  button.disabled = true;
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
    button.style.removeProperty("left");
    button.style.removeProperty("top");
    stage.classList.add("is-running");
    beginMorph();
    return;
  }

  const started = performance.now();
  const shrink = now => {
    const progress = clamp((now - started) / 400);
    const amount = smootherStep(clamp((progress - .18) / .82));
    const remaining = 1 - amount;
    // One continuous curve rounds the pill into a circle at the click.
    const width = 40 * remaining + 52 * remaining ** 3;
    // Collapse toward the click continuously after the label fades out.
    const travel = amount;
    button.style.width = `${width}px`;
    button.style.height = `${40 * remaining}px`;
    button.style.left = `${mix(fromX, toX, travel)}px`;
    button.style.top = `${mix(fromY, toY, travel)}px`;
    // Clear the label before the pill shrinks beneath it.
    startLabel.style.opacity = String(1 - smoothStep(clamp(progress / .22)));
    if (progress < 1) {
      requestAnimationFrame(shrink);
    } else {
      stage.classList.add("is-running");
      button.style.removeProperty("width");
      button.style.removeProperty("height");
      button.style.removeProperty("left");
      button.style.removeProperty("top");
      startLabel.style.removeProperty("opacity");
      beginMorph();
    }
  };
  requestAnimationFrame(shrink);
});

const selectLanguage = locale => {
  activeLanguage = locale;
  const copy = translations[locale];
  const results = resultCopy[locale];
  resultsButton.querySelector("span").textContent = results.button;
  document.querySelector("#results-title").textContent = results.title;
  document.querySelector("#results-kind").textContent = results.kind;
  document.querySelector("#results-note").textContent = results.note;
  resultsDialog.querySelector(".results-close").setAttribute("aria-label", results.close);
  document.documentElement.lang = locale;
  startLabel.textContent = copy.scan;
  button.setAttribute("aria-label", copy.scanLabel);
  islandSearch.textContent = copy.searching;
  islandFound.textContent = nativeHost && nativeScanReady && nativeCompletedAt ? copy.complete : copy.found(demoPid);
  socialMenu.toggle.setAttribute("aria-label", copy.socials);
  languageMenu.toggle.setAttribute("aria-label", copy.language);
  const flagIndex = ["en", "ru", "lt"].indexOf(locale);
  languageMenu.toggle.querySelector(".flag-track").style.transform = `translateX(${-24 * flagIndex}px)`;
  document.querySelector('[data-website]').setAttribute("aria-label", copy.website);
  languageMenu.items.forEach(item => item.setAttribute("aria-pressed", String(item.dataset.language === locale)));
  if (islandState !== "idle") {
    resizeIsland(islandState);
    scanAnnouncement.textContent = islandState === "searching" ? islandSearch.textContent : islandFound.textContent;
  }
};
languageMenu.items.forEach((item, index) => {
  item.addEventListener("click", () => {
    selectLanguage(item.dataset.language);
    languageMenu.setOpen(false);
    languageMenu.toggle.focus();
  });
  item.addEventListener("keydown", event => {
    const offsets = { ArrowDown: 1, ArrowUp: -1 };
    if (event.key in offsets) {
      event.preventDefault();
      languageMenu.items[(index + offsets[event.key] + 3) % 3].focus();
    }
  });
});
languageMenu.toggle.addEventListener("keydown", event => {
  if (event.key === "ArrowDown") {
    event.preventDefault();
    languageMenu.setOpen(true);
    requestAnimationFrame(() => {
      languageMenu.items.find(item => item.dataset.language === activeLanguage).focus();
    });
  }
});
selectLanguage("en");

// Native C++ owns scanning and report generation. The browser owns every
// visual frame, using the unmodified reference SVG/CSS renderer.
window.rootSetPid = pid => {
  demoPid = Number(pid) || 0;
  islandFound.textContent = translations[activeLanguage].found(demoPid);
};
window.rootSetProgress = progress => {
  nativeProgress = Math.max(0, Math.min(100, Math.floor(Number(progress) || 0)));
};
window.rootSetStatus = status => {
  const next = String(status || translations[activeLanguage].searching);
  const memory = /^Memory signatures: (\d+) \/ (\d+) MB$/.exec(next);
  const current = islandSearch.querySelector('[data-memory-current]');
  const total = islandSearch.querySelector('[data-memory-total]');
  // During this stage, keep the label, units, position and transition still.
  // Update only the two numeric nodes. Reserve digit space at stage entry.
  if (memory && current && total) {
    if (current.textContent !== memory[1]) current.textContent = memory[1];
    if (total.textContent !== memory[2]) total.textContent = memory[2];
    scanAnnouncement.textContent = next;
    return;
  }
  const setText = () => {
    if (!memory) { islandSearch.textContent = next; return; }
    const value = document.createElement('span');
    const limit = document.createElement('span');
    value.dataset.memoryCurrent = ''; limit.dataset.memoryTotal = '';
    value.textContent = memory[1]; limit.textContent = memory[2];
    for (const node of [value, limit]) {
      node.style.fontVariantNumeric = 'tabular-nums';
      node.style.display = 'inline-block';
      node.style.minWidth = `${memory[2].length}ch`;
      node.style.textAlign = 'right';
    }
    islandSearch.replaceChildren(document.createTextNode('Memory signatures: '), value,
      document.createTextNode(' / '), limit, document.createTextNode(' MB'));
  };
  if (islandSearch.textContent !== next) {
    if (islandState === 'searching' && islandCopyLayer.dataset.message === 'searching' &&
        !matchMedia('(prefers-reduced-motion: reduce)').matches) {
      const outgoing = islandSearch.cloneNode(true);
      outgoing.removeAttribute('id'); islandCopyLayer.append(outgoing);
      outgoing.animate([
        { opacity: 1, transform: 'translate(-50%, -50%)' },
        { opacity: 0, transform: 'translate(-50%, calc(-50% - 18px))' },
      ], { duration: 280, easing: 'cubic-bezier(.22,.8,.2,1)', fill: 'forwards' })
        .onfinish = () => outgoing.remove();
      setText();
      const incoming = islandSearch.animate([
        { opacity: 0, transform: 'translate(-50%, calc(-50% + 18px))' },
        { opacity: 1, transform: 'translate(-50%, -50%)' },
      ], { duration: 360, easing: 'cubic-bezier(.22,.8,.2,1)' });
      incoming.onfinish = () => incoming.cancel();
    } else setText();
  }
  if (islandState === 'searching') {
    resizeIsland('searching'); scanAnnouncement.textContent = islandSearch.textContent;
  }
};
window.rootScanComplete = (pid, succeeded = true) => {
  if (nativeHost && (!nativeScanActive || nativeScanReady)) return;
  window.rootSetPid(pid);
  nativeScanSucceeded = Boolean(succeeded);
  nativeProgress = 100;
  nativeCompletedAt = performance.now();
  nativeScanReady = true;
  if (nativeScanSucceeded) {
    islandFound.textContent = translations[activeLanguage].complete;
    setIsland("found");
  }
};
stage.addEventListener("pointerdown", event => {
  if (event.target === stage) nativeHost?.postMessage("drag");
});
document.addEventListener("keydown", event => {
  if (event.key === "Escape" && !document.querySelector('#socials[data-open="true"]') &&
      !document.querySelector('#languages[data-open="true"]')) nativeHost?.postMessage("close");
});

// External destinations are opened by the native host using fixed URLs.
document.querySelectorAll('[data-native-action]').forEach(link => {
  link.addEventListener('click', event => {
    if (nativeHost) { event.preventDefault(); nativeHost.postMessage(link.dataset.nativeAction); }
  });
});
