from __future__ import annotations

from html import escape
from pathlib import Path

from app.lesson_pipeline.contracts import AnimationRequest, GeneratedAsset


def _animation_graphic(concept: str) -> str:
    if concept == "unit_conversion":
        return """
        <div class="card">
          <div class="big">2.5 km</div>
          <div class="arrow">down</div>
          <div class="big pulse">2500 m</div>
        </div>
        """
    if concept == "prefix_scale":
        return """
        <div class="ladder">
          <div class="step top">kilo x1000</div>
          <div class="connector"></div>
          <div class="step middle">base unit</div>
          <div class="connector"></div>
          <div class="step bottom">milli x0.001</div>
        </div>
        """
    if concept in {"measurement_precision", "tool_trust"}:
        return """
        <div class="compare">
          <div class="box low">Ruler<br/>+/- 1 cm</div>
          <div class="vs">better</div>
          <div class="box high pulse">Caliper<br/>+/- 0.01 cm</div>
        </div>
        """
    if concept == "scalar_vector":
        return """
        <div class="compare">
          <div class="box low">6 m<br/>scalar</div>
          <div class="vs">plus direction</div>
          <div class="box high pulse">6 m east<br/>vector</div>
        </div>
        """
    if concept == "significant_figures":
        return """
        <div class="card">
          <div class="big">0.00450</div>
          <div class="arrow">keep 3 sf</div>
          <div class="big pulse">0.00450</div>
        </div>
        """
    if concept == "density_packing":
        return """
        <div class="compare">
          <div class="box low">same volume<br/>less mass</div>
          <div class="vs">pack more</div>
          <div class="box high pulse">same volume<br/>greater density</div>
        </div>
        """
    if concept == "accuracy_precision":
        return """
        <div class="compare">
          <div class="box low">tight but off target</div>
          <div class="vs">vs</div>
          <div class="box high pulse">spread around target</div>
        </div>
        """
    if concept == "energy_transfer":
        return """
        <div class="compare">
          <div class="box low">Force only<br/>0 J work</div>
          <div class="vs">vs</div>
          <div class="box high pulse">Force + motion<br/>energy transfer</div>
        </div>
        """
    if concept == "energy_stores":
        return """
        <div class="ladder">
          <div class="step top">Kinetic<br/>0.5mv^2</div>
          <div class="connector"></div>
          <div class="step middle">Height<br/>mgh</div>
          <div class="connector"></div>
          <div class="step bottom">Useful share<br/>efficiency</div>
        </div>
        """
    if concept == "power_rate":
        return """
        <div class="compare">
          <div class="box high pulse">600 J / 10 s<br/>60 W</div>
          <div class="vs">faster</div>
          <div class="box low">600 J / 20 s<br/>30 W</div>
        </div>
        """
    if concept == "current_flow":
        return """
        <div class="card">
          <div class="big">I = Q/t</div>
          <div class="arrow">loop</div>
          <div class="big pulse">V = E/Q</div>
        </div>
        """
    if concept == "series_parallel":
        return """
        <div class="compare">
          <div class="box low">Series<br/>one current</div>
          <div class="vs">split</div>
          <div class="box high pulse">Parallel<br/>branch currents</div>
        </div>
        """
    if concept == "power_safety":
        return """
        <div class="compare">
          <div class="box high pulse">P = VI<br/>rate</div>
          <div class="vs">protect</div>
          <div class="box low">Fuse trips<br/>unsafe current</div>
        </div>
        """
    if concept == "distance_time_story":
        return """
        <div class="compare">
          <div class="box low">quest lane<br/>motion</div>
          <div class="vs">record</div>
          <div class="box high pulse">mission log<br/>distance vs time</div>
        </div>
        """
    if concept == "speed_time_change":
        return """
        <div class="compare">
          <div class="box low">graph height<br/>speed now</div>
          <div class="vs">slope</div>
          <div class="box high pulse">rate of change<br/>acceleration</div>
        </div>
        """
    if concept == "signed_acceleration":
        return """
        <div class="compare">
          <div class="box low">u -> v<br/>signed change</div>
          <div class="vs">over t</div>
          <div class="box high pulse">a = (v-u)/t<br/>sign matters</div>
        </div>
        """
    if concept == "constant_acceleration_forecast":
        return """
        <div class="ladder">
          <div class="step top">knowns -> unknown</div>
          <div class="connector"></div>
          <div class="step middle">constant a?</div>
          <div class="connector"></div>
          <div class="step bottom pulse">choose the equation</div>
        </div>
        """
    if concept == "graph_gradient_context":
        return """
        <div class="compare">
          <div class="box low">same tilt<br/>distance-time = speed</div>
          <div class="vs">axes</div>
          <div class="box high pulse">same tilt<br/>speed-time = acceleration</div>
        </div>
        """
    if concept == "speed_time_area":
        return """
        <div class="compare">
          <div class="box low">rectangle<br/>base distance</div>
          <div class="vs">plus</div>
          <div class="box high pulse">triangle<br/>extra distance</div>
        </div>
        """
    return """
    <div class="card">
      <div class="big pulse">Concept animation</div>
    </div>
    """


def _build_html(title: str, description: str, concept: str, duration_sec: int) -> str:
    html = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>__TITLE__</title>
<style>
  body {
    margin: 0;
    font-family: Arial, sans-serif;
    background: radial-gradient(circle at center, #0f172a, #020617);
    color: white;
    display: flex;
    min-height: 100vh;
    align-items: center;
    justify-content: center;
  }
  .wrap {
    width: 100%;
    max-width: 1280px;
    min-height: 720px;
    padding: 48px;
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    justify-content: center;
    gap: 28px;
  }
  .title {
    text-align: center;
    font-size: 40px;
    font-weight: 800;
  }
  .desc {
    text-align: center;
    font-size: 22px;
    color: #cbd5e1;
  }
  .card, .ladder, .compare {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 24px;
    min-height: 360px;
  }
  .ladder {
    flex-direction: column;
  }
  .big {
    font-size: 72px;
    font-weight: 900;
  }
  .arrow, .vs {
    font-size: 48px;
    color: #38bdf8;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    animation: drift __DURATION__s infinite ease-in-out;
  }
  .step {
    width: 320px;
    padding: 24px;
    text-align: center;
    border-radius: 18px;
    font-size: 32px;
    font-weight: 800;
  }
  .top { background: #1d4ed8; }
  .middle { background: #166534; }
  .bottom { background: #9a3412; }
  .connector {
    width: 10px;
    height: 80px;
    background: linear-gradient(#38bdf8, #86efac);
    border-radius: 999px;
    animation: pulse __DURATION__s infinite ease-in-out;
  }
  .box {
    width: 300px;
    height: 180px;
    border-radius: 22px;
    display: flex;
    align-items: center;
    justify-content: center;
    text-align: center;
    font-size: 34px;
    font-weight: 800;
  }
  .low { background: #3f3f46; }
  .high { background: #1d4ed8; }
  .pulse {
    animation: pulse __DURATION__s infinite ease-in-out;
  }
  @keyframes pulse {
    0% { transform: scale(1); opacity: 0.90; }
    50% { transform: scale(1.05); opacity: 1; }
    100% { transform: scale(1); opacity: 0.90; }
  }
  @keyframes drift {
    0% { transform: translateY(0); }
    50% { transform: translateY(8px); }
    100% { transform: translateY(0); }
  }
</style>
</head>
<body>
  <div class="wrap">
    <div class="title">__TITLE__</div>
    <div class="desc">__DESCRIPTION__</div>
    __GRAPHIC__
  </div>
</body>
</html>
"""
    return (
        html.replace("__TITLE__", escape(title))
        .replace("__DESCRIPTION__", escape(description))
        .replace("__GRAPHIC__", _animation_graphic(concept))
        .replace("__DURATION__", str(max(4, int(duration_sec or 0))))
    )


def generate_animation(
    req: AnimationRequest,
    output_dir: str | Path,
    public_base: str,
    module_id: str,
    lesson_id: str,
) -> GeneratedAsset:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    filename = f"{req.asset_id}.html"
    path = output_path / filename
    path.write_text(
        _build_html(
            title=req.title or req.concept,
            description=req.description,
            concept=req.concept,
            duration_sec=req.duration_sec,
        ),
        encoding="utf-8",
    )

    public_url = f"{public_base.rstrip('/')}/{module_id}/{lesson_id}/animations/{filename}"

    return GeneratedAsset(
        asset_id=req.asset_id,
        kind="animation",
        phase_key=req.phase_key,
        title=req.title or req.concept,
        concept=req.concept,
        storage_path=str(path),
        public_url=public_url,
        mime_type="text/html",
        provider="local_svg_html_animation",
        meta={
            "duration_sec": int(req.duration_sec),
            "description": req.description,
            "engine": req.engine,
        },
    )
