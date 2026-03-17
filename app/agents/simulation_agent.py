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
