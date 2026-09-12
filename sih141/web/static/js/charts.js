/* charts.js -- inline SVG, hand-rolled, and the ONLY arithmetic in this app.
 *
 * WHY NO CHART LIBRARY
 * --------------------
 * Nothing on this page may be fetched from a network, ever, so a chart library
 * would have to be vendored: a megabyte of minified third-party code committed
 * into a repository whose whole claim is that it is the artefact and that every
 * number in it is covered by a test. These charts are four horizontal bars with
 * a threshold marker. Writing them costs less than auditing a bundle, they draw
 * as SVG rather than canvas -- so they stay sharp on a projector and their text
 * is real text a screen reader can reach -- and every element on them is one
 * this file put there on purpose.
 *
 * WHAT THIS FILE IS AND IS NOT ALLOWED TO DO (D8)
 * -----------------------------------------------
 * Allowed: turning a value the API supplied into a pixel coordinate. That is
 * plotting, which D8 names as permitted, and it is all `scale()` does.
 *
 * NOT allowed, and structurally prevented rather than promised:
 *
 *   * This file contains no `toFixed`, `toExponential` or `toPrecision`. It
 *     cannot format a number for display. EVERY string that reaches the screen
 *     from here arrived as a caller-supplied `label`, formatted in `format.js`
 *     from a value the API sent. A test greps for those three names.
 *   * No axis maximum is computed from the data. Every domain passed in is
 *     DEFINITIONAL -- [0, 1] for a rate, [0, 4] for CHSH, [0, trials] for a
 *     count where `trials` came from the API -- so no "nice number" chosen by a
 *     layout algorithm can ever be read as a result.
 *   * Nothing here decides a colour from a value. The caller passes a class
 *     name it derived from the API's own `signals` list; a bar is never red
 *     because this file compared it to a threshold.
 *
 * The one comparison in the file is `clamp`, which keeps a bar inside the plot
 * rectangle. It changes geometry and never a number, and a clamped bar is
 * always accompanied by its value as text in the right-hand column.
 */

const Charts = (function () {
  "use strict";

  const NS = "http://www.w3.org/2000/svg";

  const LABEL_WIDTH = 148;
  const VALUE_WIDTH = 150;
  const RIGHT_PAD = 8;
  const TOP_PAD = 36;
  const AXIS_PAD = 30;
  const ROW_HEIGHT = 34;
  const BAR_HEIGHT = 13;
  const WIDTH = 760;

  // Every chart carries its own copy of the hatch pattern, so each needs its
  // own id: three charts sharing one would put duplicate ids in the document,
  // and `url(#id)` would resolve to whichever chart happened to render first.
  // Correct today only because the three patterns are identical, and silently
  // wrong the moment one is not.
  let patternSerial = 0;

  /**
   * Create an SVG element with attributes.
   *
   * @param {string} name
   * @param {Object} attrs
   * @returns {SVGElement}
   */
  function el(name, attrs) {
    const node = document.createElementNS(NS, name);
    Object.keys(attrs || {}).forEach(function (key) {
      node.setAttribute(key, attrs[key]);
    });
    return node;
  }

  /**
   * Create an SVG text node carrying a caller-supplied string.
   *
   * `label` is never produced in this file. It is always a string the caller
   * formatted from an API value.
   *
   * @param {number} x
   * @param {number} y
   * @param {string} label
   * @param {string} className
   * @param {string} anchor
   * @returns {SVGElement}
   */
  function text(x, y, label, className, anchor) {
    const node = el("text", {
      x: x,
      y: y,
      class: className,
      "text-anchor": anchor || "start",
    });
    node.textContent = label;
    return node;
  }

  /**
   * Keep a coordinate inside the plot rectangle.
   *
   * Geometry only: a clamped bar always has its value printed as text beside
   * it, so nothing is hidden by the clamp.
   *
   * @param {number} value
   * @param {number} low
   * @param {number} high
   * @returns {number}
   */
  function clamp(value, low, high) {
    if (value < low) {
      return low;
    }
    if (value > high) {
      return high;
    }
    return value;
  }

  /**
   * Map a data value onto an x coordinate. The whole of the arithmetic.
   *
   * @param {number} value
   * @param {{min: number, max: number}} domain
   * @param {number} left
   * @param {number} right
   * @returns {number}
   */
  function scale(value, domain, left, right) {
    const span = domain.max - domain.min;
    if (span === 0) {
      return left;
    }
    const fraction = (value - domain.min) / span;
    return clamp(left + fraction * (right - left), left, right);
  }

  /**
   * Append the hatch pattern used for a cell that could not be evaluated.
   *
   * @param {SVGElement} svg
   * @param {string} id
   * @returns {void}
   */
  function addHatch(svg, id) {
    const defs = el("defs", {});
    const pattern = el("pattern", {
      id: id,
      width: 8,
      height: 8,
      patternUnits: "userSpaceOnUse",
      patternTransform: "rotate(45)",
    });
    // Colours are classes, not attributes, so the theme lives in app.css.
    pattern.appendChild(
      el("rect", { class: "hatch-ground", width: 8, height: 8 })
    );
    pattern.appendChild(
      el("line", {
        class: "hatch-line",
        x1: 0,
        y1: 0,
        x2: 0,
        y2: 8,
      })
    );
    defs.appendChild(pattern);
    svg.appendChild(defs);
  }

  /**
   * Draw a horizontal bar chart with markers and whiskers.
   *
   * @param {Object} options
   * @param {Array<Object>} options.rows One per bar. Each row carries
   *   `label` (left gutter, string), `valueLabel` (right column, string),
   *   `value` (number or null), `className` (a bar class the CALLER chose from
   *   the API's own signals), optional `interval` and `bound` objects with
   *   `low`/`high`, and optional `unavailable` (a string, which replaces the
   *   bar with a hatched cell carrying that text).
   * @param {{min: number, max: number}} options.domain Definitional, never
   *   derived from the data.
   * @param {Array<{value: number, label: string}>} options.ticks
   * @param {Array<{value: number, label: string, className: string}>}
   *   options.markers Threshold and reference lines, values from the API.
   * @param {string} options.title Accessible title for the whole figure.
   * @returns {SVGElement}
   */
  function bars(options) {
    const rows = options.rows || [];
    const domain = options.domain;
    const ticks = options.ticks || [];
    const markers = options.markers || [];
    const left = LABEL_WIDTH;
    const right = WIDTH - VALUE_WIDTH - RIGHT_PAD;
    const plotHeight = ROW_HEIGHT * rows.length;
    const height = TOP_PAD + plotHeight + AXIS_PAD;
    patternSerial += 1;
    const hatchId = `hatch-withheld-${patternSerial}`;

    const svg = el("svg", {
      class: "chart",
      viewBox: `0 0 ${WIDTH} ${height}`,
      role: "img",
      "aria-label": options.title || "chart",
    });
    const titleNode = el("title", {});
    titleNode.textContent = options.title || "chart";
    svg.appendChild(titleNode);
    addHatch(svg, hatchId);

    ticks.forEach(function (tick) {
      const x = scale(tick.value, domain, left, right);
      svg.appendChild(
        el("line", {
          class: "grid-line",
          x1: x,
          y1: TOP_PAD,
          x2: x,
          y2: TOP_PAD + plotHeight,
        })
      );
      svg.appendChild(
        text(
          x,
          TOP_PAD + plotHeight + 16,
          tick.label,
          "tick-label",
          "middle"
        )
      );
    });

    svg.appendChild(
      el("line", {
        class: "axis-line",
        x1: left,
        y1: TOP_PAD,
        x2: left,
        y2: TOP_PAD + plotHeight,
      })
    );

    // Two label lanes, alternating, so that two markers close together on
    // the axis -- the classical and Tsirelson bounds are 0.83 apart -- do not
    // print their names on top of each other.
    markers.forEach(function (marker, index) {
      const x = scale(marker.value, domain, left, right);
      const lane = index % 2 === 0 ? 12 : 26;
      svg.appendChild(
        el("line", {
          class: marker.className,
          x1: x,
          y1: lane + 4,
          x2: x,
          y2: TOP_PAD + plotHeight,
        })
      );
      svg.appendChild(
        text(
          x,
          lane,
          marker.label,
          marker.labelClassName || "marker-label",
          "middle"
        )
      );
    });

    rows.forEach(function (row, index) {
      const top = TOP_PAD + ROW_HEIGHT * index;
      const mid = top + ROW_HEIGHT / 2;

      svg.appendChild(
        text(0, mid + 4, row.label, "row-label", "start")
      );

      if (row.unavailable) {
        svg.appendChild(
          el("rect", {
            class: "hatch-cell",
            x: left,
            y: top + 5,
            width: right - left,
            height: ROW_HEIGHT - 12,
            fill: `url(#${hatchId})`,
          })
        );
        svg.appendChild(
          text(
            left + (right - left) / 2,
            mid + 4,
            row.unavailable,
            "tick-label",
            "middle"
          )
        );
      } else if (row.value !== null && row.value !== undefined) {
        // Where a bar starts. Defaults to the low end of the domain; a signed
        // quantity (CHSH runs over [-4, 4]) passes 0 so its bars grow from the
        // middle. Both are definitional constants supplied by the caller, never
        // a value read off the data.
        const base =
          options.baseline === undefined ? domain.min : options.baseline;
        const zero = scale(base, domain, left, right);
        const x = scale(row.value, domain, left, right);
        // An SVG rect is anchored at its LEFT edge, so a bar running back from
        // the baseline starts at `x` and not at `zero`. Anchoring both at
        // `zero` drew a CHSH of -2 as a bar reaching +2 -- the right length on
        // the wrong side of the zero line, on the one chart whose whole point
        // is which side of a bound a link sits.
        svg.appendChild(
          el("rect", {
            class: row.className || "bar",
            x: Math.min(zero, x),
            y: mid - BAR_HEIGHT / 2,
            width: Math.abs(x - zero),
            height: BAR_HEIGHT,
          })
        );
        if (row.bound) {
          const lo = scale(row.bound.low, domain, left, right);
          const hi = scale(row.bound.high, domain, left, right);
          svg.appendChild(
            el("line", {
              class: "whisker-loose",
              x1: lo,
              y1: mid + BAR_HEIGHT,
              x2: hi,
              y2: mid + BAR_HEIGHT,
            })
          );
        }
        if (row.interval) {
          const lo = scale(row.interval.low, domain, left, right);
          const hi = scale(row.interval.high, domain, left, right);
          svg.appendChild(
            el("line", {
              class: "whisker",
              x1: lo,
              y1: mid - BAR_HEIGHT,
              x2: hi,
              y2: mid - BAR_HEIGHT,
            })
          );
          svg.appendChild(
            el("line", {
              class: "whisker",
              x1: lo,
              y1: mid - BAR_HEIGHT - 4,
              x2: lo,
              y2: mid - BAR_HEIGHT + 4,
            })
          );
          svg.appendChild(
            el("line", {
              class: "whisker",
              x1: hi,
              y1: mid - BAR_HEIGHT - 4,
              x2: hi,
              y2: mid - BAR_HEIGHT + 4,
            })
          );
        }
      }

      svg.appendChild(
        text(
          WIDTH - RIGHT_PAD,
          mid + 4,
          row.valueLabel,
          "value-label",
          "end"
        )
      );
    });

    return svg;
  }

  /* ---------------------------------------------------------------------- *
   * The bench
   * ---------------------------------------------------------------------- */

  const XLINK = "http://www.w3.org/1999/xlink";
  const BENCH_WIDTH = 1000;
  const BENCH_HEIGHT = 520;

  /**
   * Where the three parties are bolted down. Fixed, because three is not a
   * variable: every claim the scheme makes is about a SECOND verifier, so a
   * session always has both. The layout follows the signature's own path.
   * Alice on the left, Bob top right because he is asked first, Charlie below
   * him because what Charlie scores arrives through Bob.
   */
  const MOUNTS = {
    alice: { x: 40, y: 190, w: 210, h: 140 },
    bob: { x: 750, y: 24, w: 214, h: 132 },
    charlie: { x: 750, y: 364, w: 214, h: 132 },
  };

  /**
   * Every path a message can take, each drawn FROM its source TO its target.
   *
   * Direction lives in the geometry rather than in the animation, so a photon
   * travelling `private-up` needs no second keyframe: it follows a path that
   * already runs upward. `private-up` is never drawn as a line of its own, it
   * is the same wire as `private-down` walked the other way.
   */
  const ROUTES = {
    "beam-bob": { d: "M 250 222 C 500 222, 500 70, 750 70", kind: "beam" },
    "cable-bob": { d: "M 250 262 C 520 262, 520 128, 750 128", kind: "cable" },
    "beam-charlie": {
      d: "M 250 298 C 500 298, 500 450, 750 450",
      kind: "beam",
    },
    forward: { d: "M 800 156 L 800 364", kind: "cable" },
    "private-down": { d: "M 910 156 L 910 364", kind: "private" },
    "private-up": { d: "M 910 364 L 910 156", kind: "private", hidden: true },
  };

  /**
   * The midpoint of each route, where a spliced-in adversary sits.
   *
   * Constants rather than a runtime bezier evaluation, and checked by hand:
   * a cubic's midpoint is (P0 + 3 P1 + 3 P2 + P3) / 8, which for `beam-bob`
   * is (500, 146). Evaluating it here instead would be arithmetic whose only
   * output is a position that never changes.
   */
  const SLOTS = {
    "beam-bob": [500, 146],
    "cable-bob": [515, 195],
    "beam-charlie": [500, 374],
    forward: [800, 260],
    "private-down": [910, 260],
  };

  /**
   * Append the bench's shared definitions: hazard stripes, glow, arrowhead,
   * and one addressable copy of every route for the particles to follow.
   *
   * @param {SVGElement} svg
   * @param {number} serial
   * @returns {void}
   */
  function benchDefs(svg, serial) {
    const defs = el("defs", {});

    const hazard = el("pattern", {
      id: `hazard-${serial}`,
      width: 12,
      height: 12,
      patternUnits: "userSpaceOnUse",
      patternTransform: "rotate(45)",
    });
    hazard.appendChild(
      el("rect", { class: "hazard-ground", width: 12, height: 12 })
    );
    hazard.appendChild(
      el("rect", { class: "hazard-stripe", width: 6, height: 12 })
    );
    defs.appendChild(hazard);

    const glow = el("filter", {
      id: `glow-${serial}`,
      x: "-100%",
      y: "-100%",
      width: "300%",
      height: "300%",
    });
    glow.appendChild(
      el("feGaussianBlur", { stdDeviation: 4, result: "blur" })
    );
    const merge = el("feMerge", {});
    merge.appendChild(el("feMergeNode", { in: "blur" }));
    merge.appendChild(el("feMergeNode", { in: "SourceGraphic" }));
    glow.appendChild(merge);
    defs.appendChild(glow);

    const arrow = el("marker", {
      id: `arrow-${serial}`,
      viewBox: "0 0 10 10",
      refX: 8,
      refY: 5,
      markerWidth: 6,
      markerHeight: 6,
      orient: "auto-start-reverse",
    });
    arrow.appendChild(
      el("path", { class: "arrow-head", d: "M 0 0 L 10 5 L 0 10 z" })
    );
    defs.appendChild(arrow);

    Object.keys(ROUTES).forEach(function (id) {
      defs.appendChild(
        el("path", { id: `route-${serial}-${id}`, d: ROUTES[id].d })
      );
    });

    svg.appendChild(defs);
  }

  /**
   * Put moving particles on one live route.
   *
   * Light is drawn as several glowing points close together and a classical
   * message as fewer, flatter pulses, so the two kinds of channel read
   * differently before anyone reads a label. Speed is a constant: nothing
   * about how fast a particle moves is read off the run.
   *
   * @param {SVGElement} svg
   * @param {Object} flow `{route}`.
   * @param {number} serial
   * @returns {void}
   */
  function particles(svg, flow, serial) {
    const route = ROUTES[flow.route];
    const href = `#route-${serial}-${flow.route}`;
    const isBeam = route.kind === "beam";
    const count = isBeam ? 4 : 2;
    const seconds = isBeam ? 1.6 : 2.2;
    for (let index = 0; index < count; index += 1) {
      const node = isBeam
        ? el("circle", {
            class: "photon",
            r: 5,
            filter: `url(#glow-${serial})`,
          })
        : el("rect", {
            class: `pulse is-${route.kind}`,
            x: -10,
            y: -4,
            width: 20,
            height: 8,
            rx: 4,
          });
      const motion = el("animateMotion", {
        dur: `${seconds}s`,
        repeatCount: "indefinite",
        begin: `${(-seconds / count) * index}s`,
        rotate: "auto",
      });
      const mpath = el("mpath", { href: href });
      mpath.setAttributeNS(XLINK, "xlink:href", href);
      motion.appendChild(mpath);
      node.appendChild(motion);
      svg.appendChild(node);
    }
  }

  /**
   * Draw one party's mount.
   *
   * @param {SVGElement} svg
   * @param {Object} party
   * @param {number} serial
   * @returns {void}
   */
  function mount(svg, party, serial) {
    const box = MOUNTS[party.id];
    if (!box) {
      return;
    }
    svg.appendChild(
      el("rect", {
        class: `mount ${party.className || ""} ${
          party.scanning ? "is-scanning" : ""
        }`,
        x: box.x,
        y: box.y,
        width: box.w,
        height: box.h,
        rx: 6,
      })
    );
    if (party.impersonated) {
      svg.appendChild(
        el("rect", {
          class: "mount-hazard",
          x: box.x,
          y: box.y,
          width: box.w,
          height: box.h,
          rx: 6,
          stroke: `url(#hazard-${serial})`,
        })
      );
    }
    // Bolt holes. Hardware on a breadboard is bolted at its corners, and the
    // four dots are what make a rounded rectangle read as a mount rather than
    // as one more card.
    [
      [box.x + 13, box.y + 13],
      [box.x + box.w - 13, box.y + 13],
      [box.x + 13, box.y + box.h - 13],
      [box.x + box.w - 13, box.y + box.h - 13],
    ].forEach(function (point) {
      svg.appendChild(
        el("circle", { class: "bolt", cx: point[0], cy: point[1], r: 3.5 })
      );
    });
    svg.appendChild(
      text(box.x + 26, box.y + 50, party.name, "mount-name", "start")
    );
    svg.appendChild(
      text(box.x + 26, box.y + 74, party.role || "", "mount-role", "start")
    );
    if (party.stateLabel) {
      svg.appendChild(
        text(
          box.x + 26,
          box.y + box.h - 22,
          party.stateLabel,
          `mount-state ${party.className || ""}`,
          "start"
        )
      );
    }
  }

  /**
   * Draw one adversary as a component spliced into the route it holds.
   *
   * @param {SVGElement} svg
   * @param {Object} adversary `{route, label, className}`.
   * @param {number} serial
   * @returns {void}
   */
  function component(svg, adversary, serial) {
    const slot = SLOTS[adversary.route];
    if (!slot) {
      return;
    }
    svg.appendChild(
      el("rect", {
        class: `adversary ${adversary.className || ""}`,
        x: slot[0] - 66,
        y: slot[1] - 20,
        width: 132,
        height: 40,
        rx: 5,
        stroke: `url(#hazard-${serial})`,
      })
    );
    svg.appendChild(
      text(
        slot[0],
        slot[1] + 5,
        adversary.label || "",
        "adversary-label",
        "middle"
      )
    );
  }

  /**
   * Draw the session on the bench.
   *
   * WHAT MOVES, AND WHAT IT MEANS. Particles travel the routes that are live in
   * the current phase, in the direction the message goes. They carry the order
   * of the protocol and the direction of each hop, both facts about the
   * protocol. They encode no rate, no count and no verdict, and the page that
   * uses this says so.
   *
   * WHAT IS HARNESS KNOWLEDGE. Adversaries, impersonation and a noisy link are
   * what the simulator did, and the detector never sees any of them. The
   * caller is responsible for labelling this drawing as the simulator's
   * record and keeping the detector's conclusion in a separate pane.
   *
   * @param {Object} options
   * @param {string} options.title Accessible title.
   * @param {Array<Object>} options.parties `{id, name, role, stateLabel,
   *   className, scanning, impersonated}`.
   * @param {Array<Object>} options.live `{route}`: the routes carrying a
   *   message in this phase.
   * @param {Array<Object>} options.adversaries `{route, label, className}`.
   * @param {Array<string>} options.noisy Route ids of links the simulator
   *   ran with channel noise.
   * @returns {SVGElement}
   */
  function bench(options) {
    patternSerial += 1;
    const serial = patternSerial;
    const noisy = {};
    (options.noisy || []).forEach(function (id) {
      noisy[id] = true;
    });

    const svg = el("svg", {
      class: "bench-svg",
      viewBox: `0 0 ${BENCH_WIDTH} ${BENCH_HEIGHT}`,
      role: "img",
      "aria-label": options.title || "the session",
    });
    const titleNode = el("title", {});
    titleNode.textContent = options.title || "the session";
    svg.appendChild(titleNode);
    benchDefs(svg, serial);

    Object.keys(ROUTES).forEach(function (id) {
      const route = ROUTES[id];
      if (route.hidden) {
        return;
      }
      svg.appendChild(
        el("path", {
          class: `route is-${route.kind} ${noisy[id] ? "is-noisy" : ""}`,
          d: route.d,
        })
      );
    });

    (options.live || []).forEach(function (flow) {
      const route = ROUTES[flow.route];
      if (!route) {
        return;
      }
      svg.appendChild(
        el("path", {
          class: `route-live is-${route.kind}`,
          d: route.d,
          "marker-end": `url(#arrow-${serial})`,
        })
      );
    });

    (options.live || []).forEach(function (flow) {
      if (ROUTES[flow.route]) {
        particles(svg, flow, serial);
      }
    });

    (options.parties || []).forEach(function (party) {
      mount(svg, party, serial);
    });

    (options.adversaries || []).forEach(function (adversary) {
      component(svg, adversary, serial);
    });

    return svg;
  }

  return { bars: bars, bench: bench };
})();
