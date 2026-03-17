from __future__ import annotations

from html import escape
from pathlib import Path

from app.lesson_pipeline.contracts import GeneratedAsset, SimulationRequest


P5_CDN = "https://cdn.jsdelivr.net/npm/p5/lib/p5.min.js"


def _prefix_conversion_lab(title: str, description: str) -> str:
    html = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>__TITLE__</title>
<script src="__P5_CDN__"></script>
<style>
  body {
    margin: 0;
    background: #0f172a;
    color: white;
    font-family: Arial, sans-serif;
  }
  .wrap {
    max-width: 1000px;
    margin: 0 auto;
    padding: 24px;
  }
  .controls {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin: 16px 0;
  }
  input, select, button {
    padding: 10px 12px;
    border-radius: 10px;
    border: 1px solid #334155;
    background: #111827;
    color: white;
  }
  .panel {
    border: 1px solid #334155;
    border-radius: 14px;
    padding: 16px;
    margin-top: 16px;
  }
  #sketch-holder {
    margin-top: 20px;
  }
</style>
</head>
<body>
  <div class="wrap">
    <h1>__TITLE__</h1>
    <p>__DESCRIPTION__</p>

    <div class="controls">
      <input id="inputValue" type="number" value="2.5" step="0.1" />
      <select id="fromUnit">
        <option value="km">km</option>
        <option value="m">m</option>
        <option value="cm">cm</option>
        <option value="mm">mm</option>
      </select>
      <span style="align-self:center;">to</span>
      <select id="toUnit">
        <option value="m">m</option>
        <option value="km">km</option>
        <option value="cm">cm</option>
        <option value="mm">mm</option>
      </select>
      <button onclick="convertValue()">Convert</button>
    </div>

    <div class="panel">
      <div id="result">Result will appear here.</div>
    </div>

    <div id="sketch-holder"></div>
  </div>

<script>
  const scales = {
    km: 1000,
    m: 1,
    cm: 0.01,
    mm: 0.001
  };

  function convertValue() {
    const value = Number(document.getElementById("inputValue").value || 0);
    const fromUnit = document.getElementById("fromUnit").value;
    const toUnit = document.getElementById("toUnit").value;
    const meters = value * scales[fromUnit];
    const converted = meters / scales[toUnit];
    document.getElementById("result").innerText = value + " " + fromUnit + " = " + converted + " " + toUnit;
    window.currentConvertedValue = converted;
    window.currentUnit = toUnit;
  }

  window.currentConvertedValue = 2500;
  window.currentUnit = "m";

  new p5((p) => {
    p.setup = () => {
      const canvas = p.createCanvas(900, 180);
      canvas.parent("sketch-holder");
    };

    p.draw = () => {
      p.background("#020617");
      p.stroke("#38bdf8");
      p.strokeWeight(4);
      p.line(80, 90, 820, 90);

      p.noStroke();
      p.fill("#93c5fd");
      p.textSize(18);
      p.textAlign(p.CENTER, p.CENTER);
      p.text("metric scale", 450, 40);

      const labels = ["km", "m", "cm", "mm"];
      const xs = [140, 360, 580, 800];
      for (let i = 0; i < labels.length; i += 1) {
        p.fill(labels[i] === window.currentUnit ? "#facc15" : "#e2e8f0");
        p.circle(xs[i], 90, labels[i] === window.currentUnit ? 36 : 24);
        p.fill("#0f172a");
        p.text(labels[i], xs[i], 90);
      }

      p.fill("#e2e8f0");
      p.textSize(24);
      p.text("Current output: " + window.currentConvertedValue + " " + window.currentUnit, 450, 150);
    };
  });

  convertValue();
</script>
</body>
</html>
"""
    return (
        html.replace("__TITLE__", escape(title))
        .replace("__DESCRIPTION__", escape(description))
        .replace("__P5_CDN__", P5_CDN)
    )


def _measurement_precision_lab(title: str, description: str) -> str:
    html = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>__TITLE__</title>
<script src="__P5_CDN__"></script>
<style>
  body {
    margin: 0;
    background: #0f172a;
    color: white;
    font-family: Arial, sans-serif;
  }
  .wrap {
    max-width: 1000px;
    margin: 0 auto;
    padding: 24px;
  }
  .controls {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin: 16px 0;
  }
  button {
    padding: 10px 14px;
    border-radius: 10px;
    border: 1px solid #334155;
    background: #111827;
    color: white;
  }
  .panel {
    border: 1px solid #334155;
    border-radius: 14px;
    padding: 16px;
    margin-top: 16px;
  }
</style>
</head>
<body>
  <div class="wrap">
    <h1>__TITLE__</h1>
    <p>__DESCRIPTION__</p>

    <div class="controls">
      <button onclick="selectTool('ruler')">Use rough ruler</button>
      <button onclick="selectTool('caliper')">Use precision caliper</button>
    </div>

    <div class="panel">
      <div id="result">Choose a tool to inspect the object.</div>
    </div>

    <div id="sketch-holder"></div>
  </div>

<script>
  window.selectedTool = "ruler";

  function selectTool(tool) {
    window.selectedTool = tool;
    const message = tool === "ruler"
      ? "Ruler selected: lower precision (plus or minus 1 cm)"
      : "Caliper selected: higher precision (plus or minus 0.01 cm)";
    document.getElementById("result").innerText = message;
  }

  new p5((p) => {
    p.setup = () => {
      const canvas = p.createCanvas(900, 220);
      canvas.parent("sketch-holder");
    };

    p.draw = () => {
      p.background("#020617");

      p.fill("#64748b");
      p.rect(220, 90, 460, 40, 8);

      const toolIsCaliper = window.selectedTool === "caliper";

      p.fill(toolIsCaliper ? "#1d4ed8" : "#3f3f46");
      p.rect(120, 60, 160, 100, 16);

      p.fill("white");
      p.textSize(22);
      p.textAlign(p.CENTER, p.CENTER);
      p.text(toolIsCaliper ? "Caliper" : "Ruler", 200, 110);

      p.fill("#e2e8f0");
      p.textSize(26);
      p.text(
        toolIsCaliper ? "Resolution: plus or minus 0.01 cm" : "Resolution: plus or minus 1 cm",
        600,
        110
      );
    };
  });

  selectTool("ruler");
</script>
</body>
</html>
"""
    return (
        html.replace("__TITLE__", escape(title))
        .replace("__DESCRIPTION__", escape(description))
        .replace("__P5_CDN__", P5_CDN)
    )


def _scalar_vector_lab(title: str, description: str) -> str:
    return _interactive_lab(
        title,
        description,
        """
        <label>Magnitude<input id="magnitude" type="number" value="6" step="1" /></label>
        <label>Direction
          <select id="direction">
            <option value="east">east</option>
            <option value="north">north</option>
            <option value="west">west</option>
            <option value="south">south</option>
          </select>
        </label>
        <label>Route out (m)<input id="outward" type="number" value="10" step="1" /></label>
        <label>Route back (m)<input id="backward" type="number" value="4" step="1" /></label>
        <label style="justify-content:end;"><button type="button" onclick="update()">Update story</button></label>
        """,
        """
        <div class="panel-grid">
          <div class="panel"><div>Vector description</div><div id="vector" class="value">6 m east</div></div>
          <div class="panel"><div>Distance</div><div id="distance" class="value">14 m</div></div>
          <div class="panel"><div>Displacement</div><div id="displacement" class="value">6 m east</div></div>
        </div>
        """,
        """
        function update() {
          const magnitude = Number(document.getElementById("magnitude").value || 0);
          const direction = document.getElementById("direction").value;
          const outward = Number(document.getElementById("outward").value || 0);
          const backward = Number(document.getElementById("backward").value || 0);
          const net = outward - backward;
          document.getElementById("vector").innerText = magnitude + " m " + direction;
          document.getElementById("distance").innerText = (outward + backward) + " m";
          document.getElementById("displacement").innerText = Math.abs(net) + " m " + (net >= 0 ? direction : "opposite");
          document.getElementById("note").innerText = "Distance follows the whole route. Displacement follows the start-to-finish arrow with direction.";
        }
        update();
        """,
    )


def _significant_figures_lab(title: str, description: str) -> str:
    return _interactive_lab(
        title,
        description,
        """
        <label>Raw value<input id="rawValue" type="number" value="12.349" step="0.001" /></label>
        <label>Sig figs<input id="sigFigs" type="number" value="3" min="1" max="6" step="1" /></label>
        <label>Operation
          <select id="operation">
            <option value="multiply">Multiplication rule</option>
            <option value="add">Addition rule</option>
          </select>
        </label>
        <label style="justify-content:end;"><button type="button" onclick="update()">Apply rule</button></label>
        """,
        """
        <div class="panel-grid">
          <div class="panel"><div>Rounded value</div><div id="rounded" class="value">12.3</div></div>
          <div class="panel"><div>Reporting focus</div><div id="focus" class="value" style="font-size:24px;">sig figs</div></div>
        </div>
        """,
        """
        function roundToSigFigs(value, sigFigs) {
          if (!Number.isFinite(value) || value === 0) return "0";
          return Number.parseFloat(value.toPrecision(sigFigs)).toString();
        }
        function update() {
          const rawValue = Number(document.getElementById("rawValue").value || 0);
          const sigFigs = Math.max(Number(document.getElementById("sigFigs").value || 1), 1);
          const operation = document.getElementById("operation").value;
          document.getElementById("rounded").innerText = roundToSigFigs(rawValue, sigFigs);
          document.getElementById("focus").innerText = operation === "multiply" ? "least sig figs" : "least decimal places";
          document.getElementById("note").innerText = operation === "multiply"
            ? "For multiplication and division, the least significant figures rule controls the final report."
            : "For addition and subtraction, the least decimal places rule controls the final report.";
        }
        update();
        """,
    )


def _density_packing_lab(title: str, description: str) -> str:
    return _interactive_lab(
        title,
        description,
        """
        <label>Mass (g)<input id="mass" type="number" value="40" step="5" /></label>
        <label>Volume (cm^3)<input id="volume" type="number" value="20" step="1" /></label>
        <label>Reference density<input id="reference" type="number" value="1.0" step="0.1" /></label>
        <label style="justify-content:end;"><button type="button" onclick="update()">Update density</button></label>
        """,
        """
        <div class="panel-grid">
          <div class="panel"><div>Density</div><div id="density" class="value">2 g/cm^3</div></div>
          <div class="panel"><div>Outcome</div><div id="outcome" class="value" style="font-size:24px;">Sink</div></div>
        </div>
        """,
        """
        function update() {
          const mass = Number(document.getElementById("mass").value || 0);
          const volume = Math.max(Number(document.getElementById("volume").value || 1), 0.1);
          const reference = Number(document.getElementById("reference").value || 1);
          const density = mass / volume;
          document.getElementById("density").innerText = density.toFixed(2).replace(/\\.00$/, "") + " g/cm^3";
          document.getElementById("outcome").innerText = density < reference ? "Float" : "Sink";
          document.getElementById("note").innerText = "Keep mass and volume together. Float or sink depends on density comparison, not mass alone.";
        }
        update();
        """,
    )


def _accuracy_precision_lab(title: str, description: str) -> str:
    return _interactive_lab(
        title,
        description,
        """
        <label>True value<input id="trueValue" type="number" value="10.0" step="0.1" /></label>
        <label>Mean reading<input id="meanValue" type="number" value="9.6" step="0.1" /></label>
        <label>Spread<input id="spread" type="number" value="0.2" step="0.1" /></label>
        <label style="justify-content:end;"><button type="button" onclick="update()">Classify set</button></label>
        """,
        """
        <div class="panel-grid">
          <div class="panel"><div>Accuracy</div><div id="accuracy" class="value" style="font-size:24px;">low</div></div>
          <div class="panel"><div>Precision</div><div id="precision" class="value" style="font-size:24px;">high</div></div>
          <div class="panel"><div>Uncertainty</div><div id="uncertainty" class="value">+/- 0.2</div></div>
        </div>
        """,
        """
        function update() {
          const trueValue = Number(document.getElementById("trueValue").value || 0);
          const meanValue = Number(document.getElementById("meanValue").value || 0);
          const spread = Math.abs(Number(document.getElementById("spread").value || 0));
          const bias = Math.abs(meanValue - trueValue);
          document.getElementById("accuracy").innerText = bias <= spread ? "high" : "low";
          document.getElementById("precision").innerText = spread <= 0.3 ? "high" : "low";
          document.getElementById("uncertainty").innerText = "+/- " + spread.toFixed(1).replace(/\\.0$/, "");
          document.getElementById("note").innerText = "Accuracy is about closeness to the true value. Precision is about the spread of the repeated readings.";
        }
        update();
        """,
    )


def _interactive_lab(title: str, description: str, controls_html: str, result_html: str, script: str) -> str:
    html = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>__TITLE__</title>
<style>
  body {
    margin: 0;
    background: #0f172a;
    color: white;
    font-family: Arial, sans-serif;
  }
  .wrap {
    max-width: 980px;
    margin: 0 auto;
    padding: 24px;
  }
  .controls {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    margin: 20px 0;
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 8px;
    font-size: 14px;
    color: #cbd5e1;
  }
  input, select, button {
    padding: 10px 12px;
    border-radius: 10px;
    border: 1px solid #334155;
    background: #111827;
    color: white;
  }
  .panel-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 12px;
    margin-top: 18px;
  }
  .panel {
    border: 1px solid #334155;
    border-radius: 14px;
    padding: 16px;
    background: #111827;
  }
  .value {
    font-size: 34px;
    font-weight: 800;
    color: #93c5fd;
  }
  .note {
    margin-top: 18px;
    color: #e2e8f0;
  }
</style>
</head>
<body>
  <div class="wrap">
    <h1>__TITLE__</h1>
    <p>__DESCRIPTION__</p>
    <div class="controls">__CONTROLS__</div>
    __RESULT_HTML__
    <p id="note" class="note"></p>
  </div>
  <script>
__SCRIPT__
  </script>
</body>
</html>
"""
    return (
        html.replace("__TITLE__", escape(title))
        .replace("__DESCRIPTION__", escape(description))
        .replace("__CONTROLS__", controls_html)
        .replace("__RESULT_HTML__", result_html)
        .replace("__SCRIPT__", script)
    )


def _energy_transfer_lab(title: str, description: str) -> str:
    return _interactive_lab(
        title,
        description,
        """
        <label>Force (N)<input id="force" type="number" value="5" step="1" /></label>
        <label>Distance (m)<input id="distance" type="number" value="2" step="0.5" /></label>
        <label>Motion case
          <select id="motionCase">
            <option value="same">Moves in force direction</option>
            <option value="none">Does not move</option>
            <option value="opposite">Moves opposite the force</option>
          </select>
        </label>
        <label style="justify-content:end;"><button type="button" onclick="update()">Compare case</button></label>
        """,
        """
        <div class="panel-grid">
          <div class="panel"><div>Work</div><div id="work" class="value">10 J</div></div>
          <div class="panel"><div>Transfer story</div><div id="story" class="value" style="font-size:24px;">Energy transferred</div></div>
        </div>
        """,
        """
        function update() {
          const force = Number(document.getElementById("force").value || 0);
          const distance = Number(document.getElementById("distance").value || 0);
          const motionCase = document.getElementById("motionCase").value;
          let work = 0;
          let story = "No transfer";
          if (motionCase === "same") {
            work = force * distance;
            story = "Energy transferred";
          } else if (motionCase === "opposite") {
            work = -force * distance;
            story = "Transfer opposes the motion";
          }
          document.getElementById("work").innerText = work + " J";
          document.getElementById("story").innerText = story;
          document.getElementById("note").innerText = motionCase === "none"
            ? "Force alone is not enough; without displacement there is no work transfer."
            : "Check force and displacement before calculating work.";
        }
        update();
        """,
    )


def _energy_store_lab(title: str, description: str) -> str:
    return _interactive_lab(
        title,
        description,
        """
        <label>Mass (kg)<input id="mass" type="number" value="2" step="0.5" /></label>
        <label>Speed (m/s)<input id="speed" type="number" value="4" step="0.5" /></label>
        <label>Height (m)<input id="height" type="number" value="6" step="0.5" /></label>
        <label>Useful output (%)<input id="useful" type="number" value="75" step="1" /></label>
        <label style="justify-content:end;"><button type="button" onclick="update()">Update stores</button></label>
        """,
        """
        <div class="panel-grid">
          <div class="panel"><div>Kinetic energy</div><div id="ke" class="value">16 J</div></div>
          <div class="panel"><div>GPE gain</div><div id="gpe" class="value">120 J</div></div>
          <div class="panel"><div>Efficiency</div><div id="eff" class="value">75%</div></div>
        </div>
        """,
        """
        function update() {
          const mass = Number(document.getElementById("mass").value || 0);
          const speed = Number(document.getElementById("speed").value || 0);
          const height = Number(document.getElementById("height").value || 0);
          const useful = Number(document.getElementById("useful").value || 0);
          const ke = 0.5 * mass * speed * speed;
          const gpe = mass * 10 * height;
          document.getElementById("ke").innerText = ke.toFixed(1).replace(/\\.0$/, "") + " J";
          document.getElementById("gpe").innerText = gpe.toFixed(1).replace(/\\.0$/, "") + " J";
          document.getElementById("eff").innerText = useful + "%";
          document.getElementById("note").innerText = "Doubling speed changes kinetic energy more strongly than doubling mass because speed is squared.";
        }
        update();
        """,
    )


def _power_rate_lab(title: str, description: str) -> str:
    return _interactive_lab(
        title,
        description,
        """
        <label>Energy (J)<input id="energy" type="number" value="600" step="10" /></label>
        <label>Time (s)<input id="time" type="number" value="20" step="1" /></label>
        <label>Useful share (%)<input id="share" type="number" value="60" step="1" /></label>
        <label style="justify-content:end;"><button type="button" onclick="update()">Update rate</button></label>
        """,
        """
        <div class="panel-grid">
          <div class="panel"><div>Power</div><div id="power" class="value">30 W</div></div>
          <div class="panel"><div>Useful power</div><div id="usefulPower" class="value">18 W</div></div>
          <div class="panel"><div>Total energy</div><div id="totalEnergy" class="value">600 J</div></div>
        </div>
        """,
        """
        function update() {
          const energy = Number(document.getElementById("energy").value || 0);
          const time = Math.max(Number(document.getElementById("time").value || 1), 1);
          const share = Number(document.getElementById("share").value || 0) / 100;
          const power = energy / time;
          document.getElementById("power").innerText = power.toFixed(1).replace(/\\.0$/, "") + " W";
          document.getElementById("usefulPower").innerText = (power * share).toFixed(1).replace(/\\.0$/, "") + " W";
          document.getElementById("totalEnergy").innerText = energy + " J";
          document.getElementById("note").innerText = "Power tells how fast energy is transferred. Efficiency tells how much of that transfer is useful.";
        }
        update();
        """,
    )


def _current_flow_lab(title: str, description: str) -> str:
    return _interactive_lab(
        title,
        description,
        """
        <label>Charge (C)<input id="charge" type="number" value="18" step="1" /></label>
        <label>Time (s)<input id="time" type="number" value="3" step="1" /></label>
        <label>Energy transfer (J)<input id="energy" type="number" value="24" step="1" /></label>
        <label style="justify-content:end;"><button type="button" onclick="update()">Update loop</button></label>
        """,
        """
        <div class="panel-grid">
          <div class="panel"><div>Current</div><div id="current" class="value">6 A</div></div>
          <div class="panel"><div>Potential difference</div><div id="voltage" class="value">1.3 V</div></div>
        </div>
        """,
        """
        function update() {
          const charge = Number(document.getElementById("charge").value || 0);
          const time = Math.max(Number(document.getElementById("time").value || 1), 1);
          const energy = Number(document.getElementById("energy").value || 0);
          const current = charge / time;
          const voltage = charge === 0 ? 0 : energy / charge;
          document.getElementById("current").innerText = current.toFixed(1).replace(/\\.0$/, "") + " A";
          document.getElementById("voltage").innerText = voltage.toFixed(1).replace(/\\.0$/, "") + " V";
          document.getElementById("note").innerText = "Current is charge per second. Potential difference is energy transferred per charge.";
        }
        update();
        """,
    )


def _series_parallel_lab(title: str, description: str) -> str:
    return _interactive_lab(
        title,
        description,
        """
        <label>Mode
          <select id="mode">
            <option value="series">Series</option>
            <option value="parallel">Parallel</option>
          </select>
        </label>
        <label>Voltage (V)<input id="voltage" type="number" value="12" step="1" /></label>
        <label>Resistor A (ohm)<input id="r1" type="number" value="4" step="1" /></label>
        <label>Resistor B (ohm)<input id="r2" type="number" value="6" step="1" /></label>
        <label style="justify-content:end;"><button type="button" onclick="update()">Update network</button></label>
        """,
        """
        <div class="panel-grid">
          <div class="panel"><div>Total resistance</div><div id="totalResistance" class="value">10 ohm</div></div>
          <div class="panel"><div>Total current</div><div id="totalCurrent" class="value">1.2 A</div></div>
          <div class="panel"><div>Branch A</div><div id="branchA" class="value">1.2 A</div></div>
          <div class="panel"><div>Branch B</div><div id="branchB" class="value">1.2 A</div></div>
        </div>
        """,
        """
        function update() {
          const mode = document.getElementById("mode").value;
          const voltage = Number(document.getElementById("voltage").value || 0);
          const r1 = Math.max(Number(document.getElementById("r1").value || 1), 0.1);
          const r2 = Math.max(Number(document.getElementById("r2").value || 1), 0.1);
          let totalResistance = r1 + r2;
          let branchA = 0;
          let branchB = 0;
          if (mode === "parallel") {
            totalResistance = 1 / ((1 / r1) + (1 / r2));
            branchA = voltage / r1;
            branchB = voltage / r2;
          }
          const totalCurrent = voltage / totalResistance;
          if (mode === "series") {
            branchA = totalCurrent;
            branchB = totalCurrent;
          }
          document.getElementById("totalResistance").innerText = totalResistance.toFixed(2).replace(/\\.00$/, "") + " ohm";
          document.getElementById("totalCurrent").innerText = totalCurrent.toFixed(2).replace(/\\.00$/, "") + " A";
          document.getElementById("branchA").innerText = branchA.toFixed(2).replace(/\\.00$/, "") + " A";
          document.getElementById("branchB").innerText = branchB.toFixed(2).replace(/\\.00$/, "") + " A";
          document.getElementById("note").innerText = mode === "series"
            ? "One route means the same current passes every checkpoint."
            : "Parallel branches split the current and add back to the total.";
        }
        update();
        """,
    )


def _power_safety_lab(title: str, description: str) -> str:
    return _interactive_lab(
        title,
        description,
        """
        <label>Voltage (V)<input id="voltage" type="number" value="12" step="1" /></label>
        <label>Current (A)<input id="current" type="number" value="1.5" step="0.1" /></label>
        <label>Time (s)<input id="time" type="number" value="30" step="1" /></label>
        <label>Protection limit (A)<input id="limit" type="number" value="2" step="0.1" /></label>
        <label style="justify-content:end;"><button type="button" onclick="update()">Update safety</button></label>
        """,
        """
        <div class="panel-grid">
          <div class="panel"><div>Power</div><div id="power" class="value">18 W</div></div>
          <div class="panel"><div>Energy</div><div id="energy" class="value">540 J</div></div>
          <div class="panel"><div>Protection</div><div id="status" class="value" style="font-size:24px;">Safe</div></div>
        </div>
        """,
        """
        function update() {
          const voltage = Number(document.getElementById("voltage").value || 0);
          const current = Number(document.getElementById("current").value || 0);
          const time = Number(document.getElementById("time").value || 0);
          const limit = Number(document.getElementById("limit").value || 0);
          const power = voltage * current;
          const energy = power * time;
          const tripped = current > limit;
          document.getElementById("power").innerText = power.toFixed(1).replace(/\\.0$/, "") + " W";
          document.getElementById("energy").innerText = energy.toFixed(1).replace(/\\.0$/, "") + " J";
          document.getElementById("status").innerText = tripped ? "Trip protection" : "Safe";
          document.getElementById("note").innerText = tripped
            ? "Current is above the safe limit, so the protective device should open the circuit."
            : "Power is the transfer rate, and protection depends on current staying within the safe limit.";
        }
        update();
        """,
    )


def _generic_lab(title: str, description: str) -> str:
    html = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>__TITLE__</title>
<style>
  body {
    margin: 0;
    background: #0f172a;
    color: white;
    font-family: Arial, sans-serif;
    display: grid;
    place-items: center;
    min-height: 100vh;
  }
  .panel {
    width: min(900px, 90vw);
    border: 1px solid #334155;
    border-radius: 18px;
    padding: 24px;
    background: #111827;
  }
</style>
</head>
<body>
  <div class="panel">
    <h1>__TITLE__</h1>
    <p>__DESCRIPTION__</p>
    <p>This simulation scaffold is ready for a deeper Codex-generated implementation.</p>
  </div>
</body>
</html>
"""
    return html.replace("__TITLE__", escape(title)).replace("__DESCRIPTION__", escape(description))


def _m1_shell(title: str, description: str, controls: str, figure: str, readout: str, script: str) -> str:
    html = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>__TITLE__</title>
<style>
  body { margin: 0; background: #0f172a; color: white; font-family: Arial, sans-serif; }
  .wrap { max-width: 1120px; margin: 0 auto; padding: 24px; }
  .grid { display: grid; gap: 18px; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); }
  .panel { border: 1px solid #334155; border-radius: 18px; padding: 18px; background: #111827; }
  label { display: block; margin-top: 14px; color: #cbd5e1; }
  input { width: 100%; margin-top: 8px; }
  .chips { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); margin-top: 16px; }
  .chip { border-radius: 14px; padding: 12px; background: #0f172a; border: 1px solid #334155; }
  svg { width: 100%; height: auto; display: block; }
  .note { margin-top: 16px; padding: 14px; border-radius: 14px; background: #082f49; color: #e0f2fe; }
</style>
</head>
<body>
  <div class="wrap">
    <h1>__TITLE__</h1>
    <p>__DESCRIPTION__</p>
    <div class="grid">
      <div class="panel">
        <h2>Controls</h2>
        __CONTROLS__
      </div>
      <div class="panel">
        <h2>Graph board</h2>
        __FIGURE__
        <div class="chips">__READOUT__</div>
        <div class="note" id="note"></div>
      </div>
    </div>
  </div>
<script>
__SCRIPT__
</script>
</body>
</html>
"""
    return (
        html.replace("__TITLE__", escape(title))
        .replace("__DESCRIPTION__", escape(description))
        .replace("__CONTROLS__", controls)
        .replace("__FIGURE__", figure)
        .replace("__READOUT__", readout)
        .replace("__SCRIPT__", script)
    )


def _distance_time_story_lab(title: str, description: str) -> str:
    controls = """
      <label>Opening pace (m/s)<input id="speedA" type="range" min="1" max="8" step="1" value="4" /></label>
      <label>Pause time (s)<input id="pause" type="range" min="0" max="6" step="1" value="2" /></label>
      <label>Closing pace (m/s)<input id="speedB" type="range" min="1" max="8" step="1" value="6" /></label>
    """
    figure = """
      <svg viewBox="0 0 560 280" aria-label="Distance-time story graph">
        <rect width="560" height="280" rx="18" fill="#020617" />
        <line x1="70" y1="230" x2="510" y2="230" stroke="#94a3b8" stroke-width="3" />
        <line x1="70" y1="230" x2="70" y2="40" stroke="#94a3b8" stroke-width="3" />
        <polyline id="primaryLine" fill="none" stroke="#38bdf8" stroke-width="8" stroke-linecap="round" stroke-linejoin="round" />
        <polyline id="comparisonLine" fill="none" stroke="#22c55e" stroke-width="6" stroke-dasharray="12 10" stroke-linecap="round" stroke-linejoin="round" />
        <text x="140" y="258" fill="#cbd5e1" font-size="18">time</text>
        <text x="18" y="110" fill="#cbd5e1" font-size="18" transform="rotate(-90 18 110)">distance</text>
      </svg>
    """
    readout = """
      <div class="chip"><strong>Final distance</strong><div id="finishDistance"></div></div>
      <div class="chip"><strong>Catch-up pace</strong><div id="comparisonSpeed"></div></div>
      <div class="chip"><strong>Main idea</strong><div>same finish, different story</div></div>
    """
    script = """
      function linePoints(points, width, height, maxX, maxY) {
        return points.map(([x, y]) => {
          const px = 70 + (x / Math.max(maxX, 1)) * 440;
          const py = 230 - (y / Math.max(maxY, 1)) * 170;
          return `${px},${py}`;
        }).join(' ');
      }
      function update() {
        const speedA = Number(document.getElementById('speedA').value);
        const pause = Number(document.getElementById('pause').value);
        const speedB = Number(document.getElementById('speedB').value);
        const totalTime = 8 + pause;
        const finishDistance = speedA * 4 + speedB * 4;
        const comparisonSpeed = finishDistance / totalTime;
        const mainPoints = [[0, 0], [4, speedA * 4], [4 + pause, speedA * 4], [totalTime, finishDistance]];
        const comparison = [[0, 0], [totalTime, finishDistance]];
        document.getElementById('primaryLine').setAttribute('points', linePoints(mainPoints, 560, 280, totalTime, Math.max(finishDistance, 10)));
        document.getElementById('comparisonLine').setAttribute('points', linePoints(comparison, 560, 280, totalTime, Math.max(finishDistance, 10)));
        document.getElementById('finishDistance').innerText = `${finishDistance.toFixed(0)} m`;
        document.getElementById('comparisonSpeed').innerText = `${comparisonSpeed.toFixed(2)} m/s`;
        document.getElementById('note').innerText = 'The dashed line shows a different journey that reaches the same final distance. The graph records the story; it is not the route itself.';
      }
      document.querySelectorAll('input').forEach((input) => input.addEventListener('input', update));
      update();
    """
    return _m1_shell(title, description, controls, figure, readout, script)


def _speed_time_change_lab(title: str, description: str) -> str:
    controls = """
      <label>Start speed (m/s)<input id="startSpeed" type="range" min="0" max="14" step="1" value="4" /></label>
      <label>End speed (m/s)<input id="endSpeed" type="range" min="0" max="14" step="1" value="10" /></label>
      <label>Time interval (s)<input id="duration" type="range" min="1" max="8" step="1" value="3" /></label>
    """
    figure = """
      <svg viewBox="0 0 560 280" aria-label="Speed-time graph">
        <rect width="560" height="280" rx="18" fill="#020617" />
        <line x1="70" y1="230" x2="510" y2="230" stroke="#94a3b8" stroke-width="3" />
        <line x1="70" y1="230" x2="70" y2="40" stroke="#94a3b8" stroke-width="3" />
        <polyline id="paceLine" fill="none" stroke="#38bdf8" stroke-width="8" stroke-linecap="round" stroke-linejoin="round" />
        <circle id="midPoint" r="8" fill="#fbbf24" />
        <text x="150" y="258" fill="#cbd5e1" font-size="18">time</text>
        <text x="18" y="120" fill="#cbd5e1" font-size="18" transform="rotate(-90 18 120)">speed</text>
      </svg>
    """
    readout = """
      <div class="chip"><strong>Graph height now</strong><div id="midSpeed"></div></div>
      <div class="chip"><strong>Slope</strong><div id="accel"></div></div>
      <div class="chip"><strong>Flat above zero</strong><div>constant speed</div></div>
    """
    script = """
      function update() {
        const start = Number(document.getElementById('startSpeed').value);
        const end = Number(document.getElementById('endSpeed').value);
        const duration = Number(document.getElementById('duration').value);
        const accel = (end - start) / duration;
        const maxSpeed = Math.max(start, end, 2);
        const p1 = `70,${230 - (start / maxSpeed) * 170}`;
        const p2 = `510,${230 - (end / maxSpeed) * 170}`;
        document.getElementById('paceLine').setAttribute('points', `${p1} ${p2}`);
        document.getElementById('midPoint').setAttribute('cx', '290');
        document.getElementById('midPoint').setAttribute('cy', String(230 - (((start + end) / 2) / maxSpeed) * 170));
        document.getElementById('midSpeed').innerText = `${((start + end) / 2).toFixed(1)} m/s at the midpoint`;
        document.getElementById('accel').innerText = `${accel.toFixed(2)} m/s^2`;
        document.getElementById('note').innerText = 'Height answers the speed-now question. Slope answers the rate-of-change question. They are not interchangeable.';
      }
      document.querySelectorAll('input').forEach((input) => input.addEventListener('input', update));
      update();
    """
    return _m1_shell(title, description, controls, figure, readout, script)


def _signed_acceleration_lab(title: str, description: str) -> str:
    controls = """
      <label>Initial velocity (m/s)<input id="u" type="range" min="-10" max="10" step="1" value="-6" /></label>
      <label>Final velocity (m/s)<input id="v" type="range" min="-10" max="10" step="1" value="2" /></label>
      <label>Time interval (s)<input id="t" type="range" min="1" max="8" step="1" value="4" /></label>
    """
    figure = """
      <svg viewBox="0 0 560 280" aria-label="Signed acceleration board">
        <rect width="560" height="280" rx="18" fill="#020617" />
        <line x1="80" y1="150" x2="480" y2="150" stroke="#94a3b8" stroke-width="3" />
        <line x1="280" y1="110" x2="280" y2="190" stroke="#64748b" stroke-width="3" />
        <line id="uArrow" x1="280" y1="120" x2="280" y2="120" stroke="#38bdf8" stroke-width="10" stroke-linecap="round" />
        <polygon id="uHead" points="280,120 280,120 280,120" fill="#38bdf8" />
        <line id="vArrow" x1="280" y1="190" x2="280" y2="190" stroke="#f59e0b" stroke-width="10" stroke-linecap="round" />
        <polygon id="vHead" points="280,190 280,190 280,190" fill="#f59e0b" />
      </svg>
    """
    readout = """
      <div class="chip"><strong>Signed change</strong><div id="deltaV"></div></div>
      <div class="chip"><strong>Acceleration</strong><div id="signedA"></div></div>
      <div class="chip"><strong>Sign story</strong><div id="story"></div></div>
    """
    script = """
      function arrow(lineId, headId, y, value, color) {
        const scale = 18;
        const endX = 280 + value * scale;
        const line = document.getElementById(lineId);
        line.setAttribute('x1', '280');
        line.setAttribute('y1', String(y));
        line.setAttribute('x2', String(endX));
        line.setAttribute('y2', String(y));
        const head = value >= 0
          ? `${endX},${y} ${endX - 18},${y - 10} ${endX - 18},${y + 10}`
          : `${endX},${y} ${endX + 18},${y - 10} ${endX + 18},${y + 10}`;
        document.getElementById(headId).setAttribute('points', head);
      }
      function update() {
        const u = Number(document.getElementById('u').value);
        const v = Number(document.getElementById('v').value);
        const t = Number(document.getElementById('t').value);
        const a = (v - u) / t;
        arrow('uArrow', 'uHead', 120, u, '#38bdf8');
        arrow('vArrow', 'vHead', 190, v, '#f59e0b');
        document.getElementById('deltaV').innerText = `${(v - u).toFixed(1)} m/s`;
        document.getElementById('signedA').innerText = `${a.toFixed(2)} m/s^2`;
        document.getElementById('story').innerText = a > 0 ? 'change points positive' : a < 0 ? 'change points negative' : 'no velocity change';
        document.getElementById('note').innerText = 'The sign of acceleration comes from the signed velocity change over time. It does not automatically mean “speeding up” or “slowing down” without the velocity direction.';
      }
      document.querySelectorAll('input').forEach((input) => input.addEventListener('input', update));
      update();
    """
    return _m1_shell(title, description, controls, figure, readout, script)


def _constant_acceleration_forecast_lab(title: str, description: str) -> str:
    controls = """
      <label>Initial speed u (m/s)<input id="u" type="range" min="0" max="14" step="1" value="4" /></label>
      <label>Acceleration a (m/s^2)<input id="a" type="range" min="-4" max="4" step="1" value="3" /></label>
      <label>Time t (s)<input id="t" type="range" min="1" max="8" step="1" value="2" /></label>
    """
    figure = """
      <svg viewBox="0 0 560 280" aria-label="Constant acceleration forecast board">
        <rect width="560" height="280" rx="18" fill="#020617" />
        <line x1="70" y1="230" x2="500" y2="230" stroke="#94a3b8" stroke-width="3" />
        <line x1="70" y1="230" x2="70" y2="40" stroke="#94a3b8" stroke-width="3" />
        <polygon id="areaShape" points="" fill="#38bdf8" fill-opacity="0.22" />
        <polyline id="forecastLine" fill="none" stroke="#38bdf8" stroke-width="8" stroke-linecap="round" stroke-linejoin="round" />
      </svg>
    """
    readout = """
      <div class="chip"><strong>v = u + at</strong><div id="vOut"></div></div>
      <div class="chip"><strong>s = ut + 1/2at^2</strong><div id="sOut"></div></div>
      <div class="chip"><strong>Condition</strong><div>constant acceleration</div></div>
    """
    script = """
      function update() {
        const u = Number(document.getElementById('u').value);
        const a = Number(document.getElementById('a').value);
        const t = Number(document.getElementById('t').value);
        const v = u + a * t;
        const s = u * t + 0.5 * a * t * t;
        const maxSpeed = Math.max(u, v, 2);
        const p1 = [70, 230 - (u / maxSpeed) * 170];
        const p2 = [500, 230 - (v / maxSpeed) * 170];
        document.getElementById('forecastLine').setAttribute('points', `${p1[0]},${p1[1]} ${p2[0]},${p2[1]}`);
        document.getElementById('areaShape').setAttribute('points', `70,230 70,${p1[1]} 500,${p2[1]} 500,230`);
        document.getElementById('vOut').innerText = `${v.toFixed(1)} m/s`;
        document.getElementById('sOut').innerText = `${s.toFixed(1)} m`;
        document.getElementById('note').innerText = 'This board is safe only when acceleration stays constant. Then the graph, the algebra, and the area story all agree.';
      }
      document.querySelectorAll('input').forEach((input) => input.addEventListener('input', update));
      update();
    """
    return _m1_shell(title, description, controls, figure, readout, script)


def _graph_gradient_context_lab(title: str, description: str) -> str:
    controls = """
      <label>Shared tilt<input id="gradient" type="range" min="1" max="6" step="1" value="3" /></label>
    """
    figure = """
      <svg viewBox="0 0 560 280" aria-label="Gradient context comparison">
        <rect width="560" height="280" rx="18" fill="#020617" />
        <rect x="30" y="30" width="230" height="220" rx="16" fill="#0f172a" stroke="#334155" />
        <rect x="300" y="30" width="230" height="220" rx="16" fill="#0f172a" stroke="#334155" />
        <line x1="70" y1="210" x2="220" y2="110" stroke="#38bdf8" stroke-width="8" stroke-linecap="round" />
        <line x1="340" y1="210" x2="490" y2="110" stroke="#f59e0b" stroke-width="8" stroke-linecap="round" />
        <text x="145" y="245" fill="#bfdbfe" text-anchor="middle" font-size="18">distance-time</text>
        <text x="415" y="245" fill="#fdba74" text-anchor="middle" font-size="18">speed-time</text>
      </svg>
    """
    readout = """
      <div class="chip"><strong>On distance-time</strong><div id="speedMeaning"></div></div>
      <div class="chip"><strong>On speed-time</strong><div id="accelMeaning"></div></div>
      <div class="chip"><strong>Main idea</strong><div>axes decide the rate</div></div>
    """
    script = """
      function update() {
        const gradient = Number(document.getElementById('gradient').value);
        document.getElementById('speedMeaning').innerText = `${gradient.toFixed(0)} m/s`;
        document.getElementById('accelMeaning').innerText = `${gradient.toFixed(0)} m/s^2`;
        document.getElementById('note').innerText = 'The same visual steepness can stand for different physical rates. Name the graph before naming the slope.';
      }
      document.getElementById('gradient').addEventListener('input', update);
      update();
    """
    return _m1_shell(title, description, controls, figure, readout, script)


def _speed_time_area_lab(title: str, description: str) -> str:
    controls = """
      <label>Initial speed u (m/s)<input id="u" type="range" min="0" max="10" step="1" value="2" /></label>
      <label>Final speed v (m/s)<input id="v" type="range" min="0" max="14" step="1" value="10" /></label>
      <label>Time t (s)<input id="t" type="range" min="1" max="8" step="1" value="4" /></label>
    """
    figure = """
      <svg viewBox="0 0 560 280" aria-label="Area under speed-time graph">
        <rect width="560" height="280" rx="18" fill="#020617" />
        <line x1="70" y1="230" x2="500" y2="230" stroke="#94a3b8" stroke-width="3" />
        <line x1="70" y1="230" x2="70" y2="40" stroke="#94a3b8" stroke-width="3" />
        <rect id="rectArea" x="70" y="230" width="0" height="0" fill="#60a5fa" fill-opacity="0.32" />
        <polygon id="triArea" points="" fill="#f59e0b" fill-opacity="0.45" />
        <polyline id="areaLine" fill="none" stroke="#38bdf8" stroke-width="8" stroke-linecap="round" stroke-linejoin="round" />
      </svg>
    """
    readout = """
      <div class="chip"><strong>Rectangle</strong><div id="rectOut"></div></div>
      <div class="chip"><strong>Triangle</strong><div id="triOut"></div></div>
      <div class="chip"><strong>Total distance</strong><div id="distOut"></div></div>
    """
    script = """
      function update() {
        const u = Number(document.getElementById('u').value);
        const v = Number(document.getElementById('v').value);
        const t = Number(document.getElementById('t').value);
        const rectangle = Math.min(u, v) * t;
        const triangle = 0.5 * Math.abs(v - u) * t;
        const distance = rectangle + triangle;
        const maxSpeed = Math.max(u, v, 2);
        const lineY1 = 230 - (u / maxSpeed) * 170;
        const lineY2 = 230 - (v / maxSpeed) * 170;
        document.getElementById('areaLine').setAttribute('points', `70,${lineY1} 500,${lineY2}`);
        const rectTop = 230 - (Math.min(u, v) / maxSpeed) * 170;
        document.getElementById('rectArea').setAttribute('x', '70');
        document.getElementById('rectArea').setAttribute('y', String(rectTop));
        document.getElementById('rectArea').setAttribute('width', '430');
        document.getElementById('rectArea').setAttribute('height', String(230 - rectTop));
        if (v >= u) {
          document.getElementById('triArea').setAttribute('points', `70,${lineY1} 500,${lineY1} 500,${lineY2}`);
        } else {
          document.getElementById('triArea').setAttribute('points', `70,${lineY2} 70,${lineY1} 500,${lineY2}`);
        }
        document.getElementById('rectOut').innerText = `${rectangle.toFixed(1)} m`;
        document.getElementById('triOut').innerText = `${triangle.toFixed(1)} m`;
        document.getElementById('distOut').innerText = `${distance.toFixed(1)} m`;
        document.getElementById('note').innerText = 'Each thin strip is a little piece of distance. Add every strip and you get the full journey distance from the shaded area.';
      }
      document.querySelectorAll('input').forEach((input) => input.addEventListener('input', update));
      update();
    """
    return _m1_shell(title, description, controls, figure, readout, script)


def generate_simulation(
    req: SimulationRequest,
    output_dir: str | Path,
    public_base: str,
    module_id: str,
    lesson_id: str,
) -> GeneratedAsset:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if req.concept == "measurement_precision":
        html = _measurement_precision_lab(req.title or req.concept, req.description)
    elif req.concept == "scalar_vector":
        html = _scalar_vector_lab(req.title or req.concept, req.description)
    elif req.concept == "significant_figures":
        html = _significant_figures_lab(req.title or req.concept, req.description)
    elif req.concept == "density_packing":
        html = _density_packing_lab(req.title or req.concept, req.description)
    elif req.concept == "accuracy_precision":
        html = _accuracy_precision_lab(req.title or req.concept, req.description)
    elif req.concept in {"prefix_scale", "unit_conversion"}:
        html = _prefix_conversion_lab(req.title or req.concept, req.description)
    elif req.concept == "energy_transfer":
        html = _energy_transfer_lab(req.title or req.concept, req.description)
    elif req.concept == "energy_stores":
        html = _energy_store_lab(req.title or req.concept, req.description)
    elif req.concept == "power_rate":
        html = _power_rate_lab(req.title or req.concept, req.description)
    elif req.concept == "current_flow":
        html = _current_flow_lab(req.title or req.concept, req.description)
    elif req.concept == "series_parallel":
        html = _series_parallel_lab(req.title or req.concept, req.description)
    elif req.concept == "power_safety":
        html = _power_safety_lab(req.title or req.concept, req.description)
    elif req.concept == "distance_time_story":
        html = _distance_time_story_lab(req.title or req.concept, req.description)
    elif req.concept == "speed_time_change":
        html = _speed_time_change_lab(req.title or req.concept, req.description)
    elif req.concept == "signed_acceleration":
        html = _signed_acceleration_lab(req.title or req.concept, req.description)
    elif req.concept == "constant_acceleration_forecast":
        html = _constant_acceleration_forecast_lab(req.title or req.concept, req.description)
    elif req.concept == "graph_gradient_context":
        html = _graph_gradient_context_lab(req.title or req.concept, req.description)
    elif req.concept == "speed_time_area":
        html = _speed_time_area_lab(req.title or req.concept, req.description)
    else:
        html = _generic_lab(req.title or req.concept, req.description)

    filename = "index.html"
    path = output_path / filename
    path.write_text(html, encoding="utf-8")

    public_url = f"{public_base.rstrip('/')}/{module_id}/{lesson_id}/simulations/{req.lab_id}/index.html"

    return GeneratedAsset(
        asset_id=req.asset_id,
        kind="simulation",
        phase_key=req.phase_key,
        title=req.title or req.concept,
        concept=req.concept,
        storage_path=str(path),
        public_url=public_url,
        mime_type="text/html",
        provider="local_p5_lab",
        meta={
            "lab_id": req.lab_id,
            "description": req.description,
            "engine": req.engine,
        },
    )
