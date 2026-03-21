from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

try:
    import firebase_admin
    from firebase_admin import credentials
    from google.cloud import firestore
except ModuleNotFoundError:
    firebase_admin = None
    credentials = None
    firestore = None

try:
    from scripts.lesson_authoring_contract import validate_nextgen_module
    from scripts.module_asset_pipeline import default_asset_root, plan_module_assets, render_module_assets
    from scripts.nextgen_module_scaffold import build_nextgen_module_scaffold
except ModuleNotFoundError:
    from lesson_authoring_contract import validate_nextgen_module
    from module_asset_pipeline import default_asset_root, plan_module_assets, render_module_assets
    from nextgen_module_scaffold import build_nextgen_module_scaffold

M1_MODULE_ID = "M1"
M1_CONTENT_VERSION = "20260321_m1_graph_reasoning_v5"
M1_ALLOWLIST = [
    "distance_time_story_confusion",
    "graph_shape_path_confusion",
    "graph_height_vs_gradient_confusion",
    "speed_time_story_confusion",
    "acceleration_rate_confusion",
    "acceleration_sign_reasoning_confusion",
    "suvat_selection_confusion",
    "constant_acceleration_condition_confusion",
    "motion_formula_story_confusion",
    "graph_gradient_context_confusion",
    "area_under_graph_confusion",
    "multi_representation_motion_confusion",
]
M1_SPEC = json.loads(r'''
{
  "module_description": "Module 1 uses Quest-Log to connect motion, graphs, acceleration, and constant acceleration: the lane is where motion happens, and the log is how it is recorded.",
  "mastery_outcomes": [
    "Explain why the quest lane is the motion world while the mission log is the graph world.",
    "Read progress logs conceptually and use gradient on a distance-time graph as pace.",
    "Read pace logs conceptually and connect graph slope to acceleration or deceleration.",
    "Interpret acceleration as a signed rate of velocity change, not a synonym for going faster.",
    "Choose and justify constant-acceleration equations from the motion story instead of by pattern matching.",
    "Use area under a speed-time graph as accumulated distance and compare different motion stories with the same total area."
  ],
  "lessons": [
    {
      "id": "M1_L1",
      "title": "Distance-Time Graphs and Motion Stories",
      "sim": {
        "lab_id": "m1_distance_time_story_lab",
        "title": "Distance-time story explorer",
        "description": "Use the Quest-Log lane and mission log together so students keep the motion world separate from the graph world and stop reading the graph as the shape of the route.",
        "instructions": [
          "Build one journey with a steady section, a pause, and a second steady section.",
          "Compare two segments with the same height change but different time widths.",
          "Create two graphs that finish at the same distance but tell different motion stories."
        ],
        "outcomes": [
          "distance_time_story_confusion",
          "graph_height_vs_gradient_confusion",
          "graph_shape_path_confusion"
        ],
        "fields": [
          "segment_speed_changes",
          "pause_changes",
          "same_finish_comparisons",
          "story_explanations"
        ],
        "depth": "number of graph-story comparisons that correctly separate graph height from gradient meaning"
      },
      "analogy_text": "In the Quest-Log model, the avatar moves on a quest lane while a separate mission log records the progress score at each equal clock beat. The lane is where motion happens; the log is how motion is recorded.",
      "commitment_prompt": "Before you answer, decide whether the graph is recording total distance or drawing the shape of the path.",
      "micro_prompts": [
        {
          "prompt": "Compare the quest lane with the mission log, then compare graph height with graph steepness on the mission log.",
          "hint": "Height tells the recorded distance by that time; steepness tells how quickly distance is being added."
        },
        {
          "prompt": "Compare a flat section with a road that looks flat on a map.",
          "hint": "A flat distance-time segment means the distance record stops growing, so the traveler is stopped."
        }
      ],
      "diagnostic": [
        {
          "kind": "mcq",
          "id": "M1L1_D1",
          "prompt": "On a distance-time graph, the vertical value at 8 s tells you...",
          "choices": [
            "the distance recorded by 8 s",
            "the speed at 8 s",
            "the direction of travel",
            "how steep the road is"
          ],
          "answer_index": 0,
          "hint": "Graph height on a distance-time graph tells the recorded distance, not the speed.",
          "tags": [
            "distance_time_story_confusion",
            "graph_height_vs_gradient_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L1_D2",
          "prompt": "A flat section on a distance-time graph means that the object is...",
          "choices": [
            "stopped for that interval",
            "moving backwards at constant speed",
            "accelerating steadily",
            "changing direction every second"
          ],
          "answer_index": 0,
          "hint": "If time keeps passing while distance does not change, the object is stopped.",
          "tags": [
            "distance_time_story_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L1_D3",
          "prompt": "The steeper of two straight distance-time segments shows...",
          "choices": [
            "a greater speed",
            "a larger final distance only",
            "a longer time interval only",
            "motion in reverse"
          ],
          "answer_index": 0,
          "hint": "On a distance-time graph, steeper means more distance added each second.",
          "tags": [
            "graph_height_vs_gradient_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L1_D4",
          "prompt": "The graph rises from 10 m to 34 m between 2 s and 8 s. What speed does that segment show?",
          "accepted_answers": [
            "4 m/s",
            "4"
          ],
          "hint": "Use speed = change in distance / change in time.",
          "tags": [
            "distance_time_story_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L1_D5",
          "prompt": "Two journeys finish at the same graph height, but one has a pause in the middle. This means that...",
          "choices": [
            "they can end at the same distance with different motion stories",
            "they had the same speed at every moment",
            "graph shape does not matter",
            "the paused journey must have gone farther"
          ],
          "answer_index": 0,
          "hint": "The same final distance can come from different segment stories.",
          "tags": [
            "graph_shape_path_confusion",
            "distance_time_story_confusion"
          ]
        }
      ],
      "inquiry": [
        {
          "prompt": "Keep the first segment speed fixed and change only the pause.",
          "hint": "The graph story changes even though some heights can stay the same."
        },
        {
          "prompt": "Make two graphs with the same final height but different segments.",
          "hint": "The final height alone cannot describe the whole journey."
        }
      ],
      "recon_prompts": [
        "Explain why a distance-time graph is a motion record rather than a sketch of the route.",
        "Explain what same slope but different starting height tells you about two graph segments."
      ],
      "capsule_prompt": "Read height as the record and slope as the rate before you tell the story.",
      "capsule_checks": [
        {
          "kind": "mcq",
          "id": "M1L1_C1",
          "prompt": "Two straight distance-time segments at different heights are parallel. What does that mean?",
          "choices": [
            "They show the same speed.",
            "They show the same starting point.",
            "They cover the same total distance.",
            "They must belong to the same journey."
          ],
          "answer_index": 0,
          "hint": "Parallel distance-time segments have the same gradient, so they show the same speed.",
          "tags": [
            "graph_height_vs_gradient_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L1_C2",
          "prompt": "A downward sloping line on a true total-distance-time graph would usually mean...",
          "choices": [
            "the graph is not showing total distance traveled",
            "the object is simply moving back toward the start",
            "time is running backwards",
            "the object is accelerating upward"
          ],
          "answer_index": 0,
          "hint": "Total distance traveled cannot decrease; a downward line means the graph is representing something else or has been misread.",
          "tags": [
            "graph_shape_path_confusion",
            "distance_time_story_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L1_C3",
          "prompt": "A segment adds 15 m in 5 s. What speed does it show?",
          "accepted_answers": [
            "3 m/s",
            "3"
          ],
          "hint": "Use the segment gradient as speed.",
          "tags": [
            "distance_time_story_confusion"
          ]
        }
      ],
      "transfer": [
        {
          "kind": "mcq",
          "id": "M1L1_T1",
          "prompt": "Which story best matches a graph that is steep, then flat, then less steep?",
          "choices": [
            "fast motion, then stopped, then slower motion",
            "far away, then near, then far again",
            "uphill road, then flat road, then downhill road",
            "accelerating, then constant speed, then reversing"
          ],
          "answer_index": 0,
          "hint": "Read each segment as part of a motion story.",
          "tags": [
            "distance_time_story_confusion",
            "graph_shape_path_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L1_T2",
          "prompt": "One segment rises by 50 m in 10 s and another rises by 50 m in 10 s later in the graph. Which statement is correct?",
          "choices": [
            "They show the same speed.",
            "The later segment is faster because it is higher.",
            "The earlier segment is faster because it starts lower.",
            "You cannot compare them without direction."
          ],
          "answer_index": 0,
          "hint": "Equal change in distance over equal time means equal speed.",
          "tags": [
            "graph_height_vs_gradient_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L1_T3",
          "prompt": "A runner covers 18 m in 6 s on one straight segment. What speed is shown?",
          "accepted_answers": [
            "3 m/s",
            "3"
          ],
          "hint": "Use the segment gradient.",
          "tags": [
            "distance_time_story_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L1_T4",
          "prompt": "Why is it wrong to say that a tall distance-time graph always means fast motion?",
          "choices": [
            "Because graph height gives distance, not how quickly distance is changing.",
            "Because tall graphs always mean rest.",
            "Because fast motion must make a curved line.",
            "Because only direction determines speed."
          ],
          "answer_index": 0,
          "hint": "Graph height and graph gradient answer different questions.",
          "tags": [
            "graph_height_vs_gradient_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L1_T5",
          "prompt": "Two graphs both finish at 60 m after 20 s. Graph A is one straight line. Graph B contains a pause. What must be true?",
          "choices": [
            "Graph B must have a steeper moving section somewhere to catch up.",
            "Graph A and Graph B have the same speed at every moment.",
            "Graph B covers less than 60 m in total.",
            "A pause always changes the final distance."
          ],
          "answer_index": 0,
          "hint": "If one journey pauses but still finishes at the same time and distance, it must move faster elsewhere.",
          "tags": [
            "graph_shape_path_confusion",
            "distance_time_story_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L1_T6",
          "prompt": "Which graph feature tells you that the object stopped for a while?",
          "choices": [
            "A flat section while time still increases",
            "A high point on the graph",
            "Any point above zero distance",
            "The final graph height"
          ],
          "answer_index": 0,
          "hint": "Stopped motion appears as no distance change during a time interval.",
          "tags": [
            "distance_time_story_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L1_T7",
          "prompt": "A straight line goes from 0 m at 0 s to 45 m at 15 s. What speed does it show?",
          "accepted_answers": [
            "3 m/s",
            "3"
          ],
          "hint": "Use speed = distance / time for the straight segment.",
          "tags": [
            "distance_time_story_confusion"
          ]
        }
      ],
      "contract": {
        "concept_targets": [
          "Read a distance-time graph as a running record of motion rather than a picture of a path.",
          "Use gradient to compare speeds between distance-time segments."
        ],
        "prerequisite_lessons": [],
        "misconception_focus": [
          "distance_time_story_confusion",
          "graph_shape_path_confusion",
          "graph_height_vs_gradient_confusion"
        ],
        "formulas": [
          {
            "equation": "speed = distance / time",
            "meaning": "Average or constant speed compares distance added with time taken.",
            "units": [
              "m/s"
            ],
            "conditions": "Use when the distance change and time interval are known."
          },
          {
            "equation": "gradient on a distance-time graph = change in distance / change in time",
            "meaning": "The slope of a distance-time segment tells the speed on that segment.",
            "units": [
              "m/s"
            ],
            "conditions": "Use for straight or locally straight segments on a distance-time graph."
          }
        ],
        "representations": [
          {
            "kind": "words",
            "purpose": "Tell the motion story segment by segment."
          },
          {
            "kind": "formula",
            "purpose": "Link graph gradient with speed numerically."
          },
          {
            "kind": "graph",
            "purpose": "Show height as recorded distance and slope as speed."
          }
        ],
        "analogy_map": {
          "comparison": "The quest lane is the motion world, while the mission log stands for a distance-time graph.",
          "mapping": [
            "The log height stands for the total distance recorded by that time.",
            "The steepness of the log stands for how quickly distance is being added, which is the speed."
          ],
          "limit": "The graph is not a map of hills, bends, or route shape; it only records how distance changes with time.",
          "prediction_prompt": "If the mission log goes flat for three clock beats while the lane still exists, what must the avatar be doing?"
        },
        "worked_examples": [
          {
            "prompt": "A graph rises from 0 m to 24 m in 6 s, stays flat for 4 s, then rises from 24 m to 36 m in 3 s. What story does it tell?",
            "steps": [
              "Read the first slope as steady motion because distance is increasing at a constant rate.",
              "Read the flat section as a stop because time changes while distance does not.",
              "Read the last slope and compare it with the first to decide which moving section is faster."
            ],
            "final_answer": "Move steadily, stop, then move again faster than before.",
            "why_it_matters": "The graph becomes meaningful when each segment is read as part of a motion story."
          },
          {
            "prompt": "Segment A rises from 0 m to 12 m in 4 s. Segment B rises from 20 m to 32 m in 2 s. Which segment shows the greater speed?",
            "steps": [
              "Find the gradient of Segment A: distance change = 12 m and time change = 4 s, so speed = 12 / 4 = 3 m/s.",
              "Find the gradient of Segment B: distance change = 12 m and time change = 2 s, so speed = 12 / 2 = 6 m/s.",
              "Compare the slopes: the steeper segment represents the greater speed."
            ],
            "final_answer": "Segment B is faster: Segment A shows 3 m/s and Segment B shows 6 m/s.",
            "why_it_matters": "This ties speed to slope instead of to the graph height."
          }
        ],
        "visual_assets": [
          {
            "asset_id": "m1-l1-distance-time.svg",
            "purpose": "Show height as recorded distance and slope as speed on a multi-stage distance-time graph.",
            "caption": "The route-log picture keeps graph height and graph steepness doing different jobs."
          }
        ],
        "simulation_contract": {
          "baseline_case": "Start with a segment that covers 12 m in 4 s, then pause for 2 s.",
          "comparison_tasks": [
            "Change only the pause length.",
            "Keep the final distance the same but redesign the segment story."
          ],
          "watch_for": "A distance-time graph records how distance changes; it does not sketch the shape of the route.",
          "takeaway": "Graph height tells recorded distance, while graph steepness tells speed."
        },
        "reflection_prompts": [
          "Explain why a distance-time graph can end at the same final distance yet represent a different journey story."
        ],
        "mastery_skills": [
          "Interpret a distance-time graph segment by segment.",
          "Use gradient to calculate speed from a straight segment.",
          "Distinguish graph height from graph steepness.",
          "Recognize stopped intervals from flat sections.",
          "Reject the idea that the graph is a picture of the route."
        ],
        "variation_plan": {
          "diagnostic": "Rotate graph-height, flat-section, slope, and same-finish-different-story prompts.",
          "concept_gate": "Swap between parallel-segment reasoning, downward-line judgment, and segment-gradient calculation.",
          "mastery": "Blend motion-story interpretation, slope calculation, and misconception checks without reusing the diagnostic stem wording."
        }
      }
    },
    {
      "id": "M1_L2",
      "title": "Speed-Time Graphs and Changing Motion",
      "sim": {
        "lab_id": "m1_speed_time_story_lab",
        "title": "Speed-time change explorer",
        "description": "Use the Quest-Log pace log to keep speed-now and change-of-speed separate, so graph height and graph slope stop collapsing into one idea.",
        "instructions": [
          "Build one graph with a flat section, one with a gentle rise, and one with a steep rise.",
          "Compare a downward slope with a reverse-motion guess.",
          "Keep the start speed fixed and compare two different slope sizes."
        ],
        "outcomes": [
          "speed_time_story_confusion",
          "graph_height_vs_gradient_confusion",
          "acceleration_rate_confusion"
        ],
        "fields": [
          "speed_level_changes",
          "slope_changes",
          "slowing_cases",
          "story_explanations"
        ],
        "depth": "number of speed-time graph stories explained using both height and slope correctly"
      },
      "analogy_text": "The Quest-Log pace log records the avatar's pace meter beat by beat. The graph height at any chosen beat tells the speed at that beat, while the slope over a chosen interval tells how quickly the pace is changing during that interval.",
      "commitment_prompt": "Before you interpret the graph, decide whether you are reading the speed level or the way the speed level is changing.",
      "micro_prompts": [
        {
          "prompt": "Compare pace-log height with pace-log slope before you describe the motion story.",
          "hint": "Height at a chosen time tells the speed at that time; slope over a chosen interval tells how quickly the speed is changing during that interval."
        },
        {
          "prompt": "Compare a downward sloping speed-time line with reverse travel.",
          "hint": "On a speed-time graph, a downward slope means slowing down, not moving backwards."
        }
      ],
      "diagnostic": [
        {
          "kind": "mcq",
          "id": "M1L2_D1",
          "prompt": "On a speed-time graph, the vertical value at a given time tells you...",
          "choices": [
            "the speed at that instant",
            "the distance traveled by that time",
            "the direction of motion automatically",
            "the total acceleration over the journey"
          ],
          "answer_index": 0,
          "hint": "Read the graph height at one chosen time as the speed at that time.",
          "tags": [
            "speed_time_story_confusion",
            "graph_height_vs_gradient_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L2_D2",
          "prompt": "A horizontal line above the time axis on a speed-time graph means the object is...",
          "choices": [
            "moving at constant speed",
            "stopped",
            "speeding up steadily",
            "moving backwards"
          ],
          "answer_index": 0,
          "hint": "A flat speed-time line means the speed is not changing.",
          "tags": [
            "speed_time_story_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L2_D3",
          "prompt": "A line sloping down to zero on a speed-time graph means the object is...",
          "choices": [
            "slowing to rest",
            "moving backward faster and faster",
            "stopped the whole time",
            "changing direction each second"
          ],
          "answer_index": 0,
          "hint": "A downward slope on a speed-time graph shows the speed decreasing.",
          "tags": [
            "speed_time_story_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L2_D4",
          "prompt": "A speed rises from 4 m/s to 10 m/s in 3 s. What average acceleration does this show?",
          "accepted_answers": [
            "2 m/s^2",
            "2"
          ],
          "hint": "Use change in speed divided by time.",
          "tags": [
            "acceleration_rate_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L2_D5",
          "prompt": "Which line shows the greatest acceleration on a speed-time graph?",
          "choices": [
            "the steepest upward line",
            "the highest horizontal line",
            "the line that starts at zero only",
            "the longest line"
          ],
          "answer_index": 0,
          "hint": "On a speed-time graph, steeper upward slope means a larger rate of speed change.",
          "tags": [
            "acceleration_rate_confusion",
            "graph_height_vs_gradient_confusion"
          ]
        }
      ],
      "inquiry": [
        {
          "prompt": "Keep the starting speed fixed and compare a gentle rise with a steep rise.",
          "hint": "The steeper rise means the speed is increasing more quickly."
        },
        {
          "prompt": "Build one downward slope that stays above zero.",
          "hint": "The object is still moving, but it is slowing down."
        }
      ],
      "recon_prompts": [
        "Explain why graph height and graph slope have different meanings on a speed-time graph.",
        "Explain why a downward speed-time slope does not mean reverse motion."
      ],
      "capsule_prompt": "Read the speed level first, then read how the speed level changes.",
      "capsule_checks": [
        {
          "kind": "mcq",
          "id": "M1L2_C1",
          "prompt": "Two speed-time graphs reach the same height at one instant but have different slopes there. What is the same at that instant?",
          "choices": [
            "their speed",
            "their acceleration",
            "their distance traveled",
            "their total time"
          ],
          "answer_index": 0,
          "hint": "Same graph height at the same kind of graph means same speed at that instant.",
          "tags": [
            "graph_height_vs_gradient_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L2_C2",
          "prompt": "Why is a downward slope on a speed-time graph not enough to prove reverse motion?",
          "choices": [
            "Because the graph shows speed changing, while direction is not shown on a speed-time graph.",
            "Because all downward slopes mean the journey ended.",
            "Because speed-time graphs cannot show acceleration.",
            "Because every slope on a speed-time graph represents distance."
          ],
          "answer_index": 0,
          "hint": "A speed-time graph tells speed and change rate, not direction by itself.",
          "tags": [
            "speed_time_story_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L2_C3",
          "prompt": "A speed falls from 12 m/s to 6 m/s in 3 s. What average acceleration does this show?",
          "accepted_answers": [
            "-2 m/s^2",
            "-2"
          ],
          "hint": "Use final minus initial over time.",
          "tags": [
            "acceleration_rate_confusion"
          ]
        }
      ],
      "transfer": [
        {
          "kind": "mcq",
          "id": "M1L2_T1",
          "prompt": "A horizontal line at 5 m/s for 8 s means that the object is...",
          "choices": [
            "moving steadily at 5 m/s for the whole 8 s",
            "speeding up to 5 m/s by the end",
            "stopped because the line is flat",
            "traveling 5 m in total"
          ],
          "answer_index": 0,
          "hint": "Flat on a speed-time graph means constant speed, not zero speed unless the line is on the axis.",
          "tags": [
            "speed_time_story_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L2_T2",
          "prompt": "Two rising lines start at the same speed. The steeper one shows...",
          "choices": [
            "greater acceleration",
            "greater distance automatically",
            "lower final speed",
            "reverse motion"
          ],
          "answer_index": 0,
          "hint": "Steeper on a speed-time graph means the speed changes faster.",
          "tags": [
            "acceleration_rate_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L2_T3",
          "prompt": "Why is it wrong to read the final graph height as the total distance traveled?",
          "choices": [
            "Because graph height is speed, not accumulated distance.",
            "Because only graph color shows distance.",
            "Because total distance is always zero at the end.",
            "Because tall graphs always mean long time."
          ],
          "answer_index": 0,
          "hint": "Speed-time graph height answers a speed question, not a total-distance question.",
          "tags": [
            "graph_height_vs_gradient_confusion",
            "speed_time_story_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L2_T4",
          "prompt": "A speed changes from 6 m/s to 12 m/s in 2 s. What average acceleration does this show?",
          "accepted_answers": [
            "3 m/s^2",
            "3"
          ],
          "hint": "Use change in speed divided by time.",
          "tags": [
            "acceleration_rate_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L2_T5",
          "prompt": "A graph rises gently for 4 s and then rises more steeply for 2 s. Which story fits best?",
          "choices": [
            "The object is speeding up, then speeding up more quickly.",
            "The object is moving backward, then forward.",
            "The object is stopped, then moving at constant speed.",
            "The object covers the same distance each second all the way through."
          ],
          "answer_index": 0,
          "hint": "Compare how quickly the pace log climbs in each section and keep that separate from the pace value itself.",
          "tags": [
            "speed_time_story_confusion",
            "acceleration_rate_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L2_T6",
          "prompt": "A line falls from 10 m/s to 4 m/s while remaining above the axis. Which statement is correct?",
          "choices": [
            "The object is still moving but slowing down.",
            "The object is moving backward faster and faster.",
            "The object is stopped for the whole interval.",
            "The object has zero speed throughout."
          ],
          "answer_index": 0,
          "hint": "The speed stays positive but smaller, so the object is slowing while still moving.",
          "tags": [
            "speed_time_story_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L2_T7",
          "prompt": "Two objects both show flat speed-time lines, one at 3 m/s and one at 7 m/s. What can you say?",
          "choices": [
            "Both move at constant speed, but the second is faster.",
            "Both have the same acceleration and the same speed.",
            "The lower line means the first object is stopped.",
            "The higher line must mean a longer journey in every case."
          ],
          "answer_index": 0,
          "hint": "Flat lines mean constant speed; height tells which constant speed is larger.",
          "tags": [
            "speed_time_story_confusion",
            "graph_height_vs_gradient_confusion"
          ]
        }
      ],
      "contract": {
        "concept_targets": [
          "Read a speed-time graph as a record of current speed changing with time.",
          "Use slope to compare rates of speed change without confusing slope with graph height."
        ],
        "prerequisite_lessons": [
          "M1_L1"
        ],
        "misconception_focus": [
          "speed_time_story_confusion",
          "graph_height_vs_gradient_confusion",
          "acceleration_rate_confusion"
        ],
        "formulas": [
          {
            "equation": "average acceleration = change in speed / time",
            "meaning": "A speed-time graph slope tells how quickly speed changes.",
            "units": [
              "m/s^2"
            ],
            "conditions": "Use on a straight speed-time segment or across a stated interval."
          },
          {
            "equation": "distance for a constant-speed section = speed x time",
            "meaning": "A flat speed-time section keeps the same speed throughout the interval.",
            "units": [
              "m"
            ],
            "conditions": "Use for a constant-speed section before area under the graph is generalized."
          }
        ],
        "representations": [
          {
            "kind": "words",
            "purpose": "Tell the story of steady speed, speeding up, and slowing down."
          },
          {
            "kind": "formula",
            "purpose": "Link slope to average acceleration quantitatively."
          },
          {
            "kind": "graph",
            "purpose": "Separate graph height from graph slope on a speed-time graph."
          }
        ],
        "analogy_map": {
          "comparison": "The pace log in Quest-Log stands for a speed-time graph.",
          "mapping": [
            "The height of the strip at a chosen beat stands for the speed at that beat.",
            "The tilt of the strip stands for how quickly the speed is changing."
          ],
          "limit": "The graph does not show direction automatically, so a downward slope means slowing down, not reverse travel by itself.",
          "prediction_prompt": "If the pace log stays horizontal at 6 units for five beats, what should the avatar's motion be like on the lane?"
        },
        "worked_examples": [
          {
            "prompt": "A speed-time graph is flat at 6 m/s for 4 s, then rises steadily to 12 m/s by 7 s. What story does it tell?",
            "steps": [
              "Read the flat section first as constant speed.",
              "Read the later upward slope as speeding up because the speed level is increasing.",
              "Compare the slope direction and graph height so you do not confuse speed with acceleration."
            ],
            "final_answer": "Move steadily at 6 m/s, then speed up to 12 m/s.",
            "why_it_matters": "Students need to see that graph height and graph slope answer different motion questions."
          },
          {
            "prompt": "A speed-time graph falls steadily from 12 m/s to 4 m/s in 4 s. What does that tell you about the motion?",
            "steps": [
              "Read the graph height first: the object starts at 12 m/s and ends at 4 m/s.",
              "Read the downward slope next: the speed is decreasing, so the object is slowing down.",
              "Use the slope for the average acceleration: (4 - 12) / 4 = -2 m/s^2."
            ],
            "final_answer": "The object slows from 12 m/s to 4 m/s, with average acceleration -2 m/s^2.",
            "why_it_matters": "This keeps direction separate from a graph that only records speed."
          }
        ],
        "visual_assets": [
          {
            "asset_id": "m1-l2-speed-time.svg",
            "purpose": "Show flat, rising, and falling speed-time segments with separate labels for height and slope meaning.",
            "caption": "The speed-strip picture keeps current speed and rate of change distinct."
          }
        ],
        "simulation_contract": {
          "baseline_case": "Start with a flat 4 m/s section and then add a rising section to 10 m/s.",
          "comparison_tasks": [
            "Compare a gentle rise with a steeper rise.",
            "Compare a falling section that stays above zero with a flat section."
          ],
          "watch_for": "On a speed-time graph, height tells speed and slope tells change rate; do not swap them.",
          "takeaway": "Speed-time graphs make changing speed visible only when height and slope are read separately."
        },
        "reflection_prompts": [
          "Explain why a downward line on a speed-time graph does not automatically mean the object has reversed direction."
        ],
        "mastery_skills": [
          "Interpret flat, rising, and falling speed-time segments.",
          "Use change in speed over time to find average acceleration.",
          "Distinguish graph height from graph slope on a speed-time graph.",
          "Reject reverse-motion readings that come from slope direction alone.",
          "Compare different acceleration sizes from graph steepness."
        ],
        "variation_plan": {
          "diagnostic": "Rotate height, flat-line, downward-line, simple acceleration, and steepness-comparison prompts.",
          "concept_gate": "Swap between same-height-different-slope, downward-slope meaning, and average-acceleration calculation.",
          "mastery": "Blend graph reading, reasoning, and light calculation without repeating the same speed-time stem."
        }
      }
    },
    {
      "id": "M1_L3",
      "title": "Acceleration as a Rate of Change",
      "sim": {
        "lab_id": "m1_acceleration_rate_lab",
        "title": "Acceleration rate explorer",
        "description": "Use signed pace arrows and boost shift so acceleration becomes a directional rate of velocity change rather than a vague idea of getting faster.",
        "instructions": [
          "Compare one case that speeds up in the positive direction with one that slows down in that direction.",
          "Reverse the direction convention and explain how the sign changes.",
          "Create one zero-acceleration case that is still moving."
        ],
        "outcomes": [
          "acceleration_rate_confusion",
          "acceleration_sign_reasoning_confusion",
          "multi_representation_motion_confusion"
        ],
        "fields": [
          "initial_velocity_changes",
          "final_velocity_changes",
          "sign_convention_changes",
          "zero_acceleration_cases"
        ],
        "depth": "number of acceleration cases explained using signed velocity change rather than a speed-only rule"
      },
      "analogy_text": "Quest-Log's boost shift compares the pace arrow from one beat to the next. It tracks how the signed velocity changes over time, so the sign comes from the chosen positive direction, not from a guess about whether the avatar feels faster.",
      "commitment_prompt": "Before deciding whether acceleration is positive, negative, or zero, choose the positive direction and compare the final velocity with the initial velocity.",
      "micro_prompts": [
        {
          "prompt": "Compare a case with constant non-zero velocity and a case with zero velocity.",
          "hint": "Zero acceleration means velocity is not changing; it does not require the velocity to be zero."
        },
        {
          "prompt": "Compare velocity direction with acceleration direction.",
          "hint": "Acceleration tells the direction of the velocity change, not simply whether the speed feels larger."
        }
      ],
      "diagnostic": [
        {
          "kind": "mcq",
          "id": "M1L3_D1",
          "prompt": "Acceleration is best described as...",
          "choices": [
            "the rate of change of velocity",
            "the same thing as speed",
            "distance per second",
            "force divided by distance"
          ],
          "answer_index": 0,
          "hint": "Acceleration tracks how velocity changes over time.",
          "tags": [
            "acceleration_rate_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L3_D2",
          "prompt": "Take east as positive. Velocity changes from +6 m/s to +2 m/s in 2 s. What is the acceleration?",
          "choices": [
            "-2 m/s^2",
            "+2 m/s^2",
            "-4 m/s^2",
            "0 m/s^2"
          ],
          "answer_index": 0,
          "hint": "Use final minus initial over time and keep the sign.",
          "tags": [
            "acceleration_sign_reasoning_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L3_D3",
          "prompt": "Zero acceleration means that the object is...",
          "choices": [
            "moving with constant velocity or at rest",
            "always at rest",
            "always speeding up",
            "changing direction continuously"
          ],
          "answer_index": 0,
          "hint": "Zero acceleration means no change in velocity.",
          "tags": [
            "acceleration_rate_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L3_D4",
          "prompt": "A car is moving east but slowing down. Its acceleration must point...",
          "choices": [
            "west",
            "east",
            "north",
            "nowhere because slowing has no direction"
          ],
          "answer_index": 0,
          "hint": "If velocity is east and the speed is shrinking, the velocity change points west.",
          "tags": [
            "acceleration_sign_reasoning_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L3_D5",
          "prompt": "Take east as positive. Velocity changes from -3 m/s to +5 m/s in 4 s. What is the acceleration?",
          "accepted_answers": [
            "2 m/s^2",
            "2"
          ],
          "hint": "Use the signed velocity change divided by time.",
          "tags": [
            "acceleration_sign_reasoning_confusion",
            "acceleration_rate_confusion"
          ]
        }
      ],
      "inquiry": [
        {
          "prompt": "Keep the time interval fixed and compare a positive velocity change with a negative one.",
          "hint": "The sign comes from the signed change in velocity, not from a guess about speeding up."
        },
        {
          "prompt": "Make a moving case with zero acceleration.",
          "hint": "An object can move with constant non-zero velocity while acceleration stays zero."
        }
      ],
      "recon_prompts": [
        "Explain why acceleration is a change-in-velocity idea rather than a speed-only idea.",
        "Explain why zero acceleration does not force an object to be stationary."
      ],
      "capsule_prompt": "Find the signed velocity change first, then divide by time and interpret the sign.",
      "capsule_checks": [
        {
          "kind": "mcq",
          "id": "M1L3_C1",
          "prompt": "If velocity and acceleration point in the same direction, the object is usually...",
          "choices": [
            "speeding up in that direction",
            "stopped",
            "turning with zero acceleration",
            "guaranteed to have zero velocity"
          ],
          "answer_index": 0,
          "hint": "When acceleration changes velocity in the same direction as the motion, the speed usually grows.",
          "tags": [
            "acceleration_sign_reasoning_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L3_C2",
          "prompt": "If velocity and acceleration point in opposite directions, the object is usually...",
          "choices": [
            "slowing down",
            "speeding up in the same direction",
            "guaranteed to reverse instantly",
            "stationary"
          ],
          "answer_index": 0,
          "hint": "Opposite directions mean the velocity magnitude is being reduced.",
          "tags": [
            "acceleration_sign_reasoning_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L3_C3",
          "prompt": "Velocity is 10 m/s at first and 10 m/s after 5 s. What acceleration does this show?",
          "accepted_answers": [
            "0 m/s^2",
            "0"
          ],
          "hint": "No change in velocity means zero acceleration.",
          "tags": [
            "acceleration_rate_confusion"
          ]
        }
      ],
      "transfer": [
        {
          "kind": "mcq",
          "id": "M1L3_T1",
          "prompt": "Why can a change of direction count as acceleration even if the speed stays the same?",
          "choices": [
            "Because velocity includes direction, so changing direction changes velocity.",
            "Because acceleration only depends on distance.",
            "Because speed and velocity always mean the same thing.",
            "Because direction change removes time from the motion."
          ],
          "answer_index": 0,
          "hint": "Acceleration depends on velocity change, and velocity includes direction.",
          "tags": [
            "acceleration_rate_confusion",
            "multi_representation_motion_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L3_T2",
          "prompt": "Take north as positive. Velocity changes from -4 m/s to -10 m/s in 3 s. Which statement is correct?",
          "choices": [
            "Acceleration is -2 m/s^2 and the object speeds up southward.",
            "Acceleration is +2 m/s^2 and the object slows down.",
            "Acceleration is zero because both velocities are south.",
            "Acceleration is -6 m/s^2 because only the speeds matter."
          ],
          "answer_index": 0,
          "hint": "Keep the signs on both velocities before subtracting.",
          "tags": [
            "acceleration_sign_reasoning_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L3_T3",
          "prompt": "Take east as positive. Velocity changes from +8 m/s to 0 m/s in 4 s. What acceleration does this show?",
          "accepted_answers": [
            "-2 m/s^2",
            "-2"
          ],
          "hint": "Use final minus initial over time.",
          "tags": [
            "acceleration_sign_reasoning_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L3_T4",
          "prompt": "Which statement about zero acceleration is correct?",
          "choices": [
            "It means the velocity is constant, which can include rest or steady motion.",
            "It means the object must be moving at zero speed.",
            "It means a force is impossible.",
            "It means the object changes direction every second."
          ],
          "answer_index": 0,
          "hint": "Zero acceleration means no change in velocity.",
          "tags": [
            "acceleration_rate_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L3_T5",
          "prompt": "An object has negative acceleration. Which statement must be true?",
          "choices": [
            "The acceleration points in the negative direction, but the object might be speeding up or slowing down depending on its velocity.",
            "The object must be slowing down.",
            "The object must be moving in the positive direction.",
            "The object must be at rest."
          ],
          "answer_index": 0,
          "hint": "The sign of acceleration alone does not decide whether the speed grows or shrinks.",
          "tags": [
            "acceleration_sign_reasoning_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L3_T6",
          "prompt": "If velocity is positive and acceleration is negative, the object could be...",
          "choices": [
            "moving in the positive direction while slowing down",
            "moving in the positive direction while guaranteed to speed up",
            "stationary with positive speed",
            "free from any change in velocity"
          ],
          "answer_index": 0,
          "hint": "Opposite velocity and acceleration directions usually mean slowing down.",
          "tags": [
            "acceleration_sign_reasoning_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L3_T7",
          "prompt": "Take east as positive. Velocity changes from +4 m/s to -4 m/s in 2 s. What acceleration does this show?",
          "accepted_answers": [
            "-4 m/s^2",
            "-4"
          ],
          "hint": "Use the signed change in velocity: final minus initial.",
          "tags": [
            "acceleration_sign_reasoning_confusion",
            "acceleration_rate_confusion"
          ]
        }
      ],
      "contract": {
        "concept_targets": [
          "Interpret acceleration as the rate of change of velocity, including direction.",
          "Use signed velocity changes and sign conventions to reason about acceleration correctly."
        ],
        "prerequisite_lessons": [
          "M1_L2"
        ],
        "misconception_focus": [
          "acceleration_rate_confusion",
          "acceleration_sign_reasoning_confusion",
          "multi_representation_motion_confusion"
        ],
        "formulas": [
          {
            "equation": "a = (v - u) / t",
            "meaning": "Acceleration measures how much the velocity changes each second.",
            "units": [
              "m/s^2"
            ],
            "conditions": "Use when initial velocity, final velocity, and time interval are known."
          },
          {
            "equation": "v = u + at",
            "meaning": "Final velocity can be predicted when acceleration is constant over the interval.",
            "units": [
              "m/s"
            ],
            "conditions": "Use when the acceleration stays constant during the interval."
          }
        ],
        "representations": [
          {
            "kind": "words",
            "purpose": "Explain acceleration through signed velocity change."
          },
          {
            "kind": "formula",
            "purpose": "Quantify acceleration with signed velocities."
          },
          {
            "kind": "diagram",
            "purpose": "Use velocity arrows and sign convention labels to interpret the change."
          }
        ],
        "analogy_map": {
          "comparison": "The pace arrow stands for velocity, and boost shift stands for acceleration.",
          "mapping": [
            "The initial and final velocity arrows stand for the start and end motion states.",
            "The dial direction stands for the direction of the velocity change, which is the acceleration sign."
          ],
          "limit": "Acceleration is not just a feeling of getting faster; the model is only useful when the signed velocity change is tracked carefully.",
          "prediction_prompt": "If the avatar is moving west but the boost shift points east, what can happen to the speed?"
        },
        "worked_examples": [
          {
            "prompt": "Take east as positive. A cyclist changes from +10 m/s to +4 m/s in 3 s. Find the acceleration and explain the sign.",
            "steps": [
              "Write the initial and final velocities with signs.",
              "Calculate the signed change: 4 - 10 = -6 m/s.",
              "Divide by 3 s to get -2 m/s^2, then interpret the negative sign as a velocity change toward the west."
            ],
            "final_answer": "-2 m/s^2",
            "why_it_matters": "The sign belongs to the velocity change, not to a guess about whether motion feels faster or slower."
          },
          {
            "prompt": "Take east as positive. A boat moves west at 5 m/s and keeps that same velocity for 6 s. What is the acceleration, and what does it mean?",
            "steps": [
              "Write the velocity with sign: west is negative, so the boat starts at -5 m/s and ends at -5 m/s.",
              "Find the change in velocity: -5 - (-5) = 0 m/s.",
              "Divide by the time: 0 / 6 = 0 m/s^2, so the boat has no acceleration even though it is still moving."
            ],
            "final_answer": "The acceleration is 0 m/s^2; the boat is moving west at a constant velocity of -5 m/s.",
            "why_it_matters": "Zero acceleration means no change in velocity, not necessarily no motion."
          }
        ],
        "visual_assets": [
          {
            "asset_id": "m1-l3-acceleration.svg",
            "purpose": "Show velocity arrows, sign convention, and acceleration direction as a change story.",
            "caption": "The change-rate diagram makes signed velocity change visible before calculation."
          }
        ],
        "simulation_contract": {
          "baseline_case": "Start with +4 m/s changing to +10 m/s in 3 s.",
          "comparison_tasks": [
            "Reverse the sign convention and compare the reported sign.",
            "Build a zero-acceleration case with non-zero velocity."
          ],
          "watch_for": "Acceleration is about how velocity changes, so sign conventions and direction matter.",
          "takeaway": "Zero acceleration means no change in velocity, while sign tells the direction of the velocity change."
        },
        "reflection_prompts": [
          "Explain how an object can have zero acceleration without being at rest."
        ],
        "mastery_skills": [
          "Calculate acceleration from signed velocities and time.",
          "Interpret acceleration sign using a chosen direction convention.",
          "Distinguish zero acceleration from zero velocity.",
          "Explain why direction change counts as acceleration.",
          "Reason about speeding up and slowing down from velocity and acceleration directions."
        ],
        "variation_plan": {
          "diagnostic": "Rotate definition, sign, zero-acceleration, direction-of-acceleration, and signed-change prompts.",
          "concept_gate": "Swap between speed-up/slow-down reasoning, zero-acceleration judgment, and signed-change calculation.",
          "mastery": "Blend sign conventions, verbal reasoning, and short calculations without repeating the diagnostic wording."
        }
      }
    },
    {
      "id": "M1_L4",
      "title": "Equations of Motion Under Constant Acceleration",
      "sim": {
        "lab_id": "m1_suvat_console_lab",
        "title": "Constant-acceleration equation explorer",
        "description": "Use the Quest-Log forecast board to choose equations from the motion story, but only after checking that the boost shift stays constant.",
        "instructions": [
          "Choose one case where final speed is unknown and one where time is unknown.",
          "Compare a constant-acceleration case with a changing-acceleration story.",
          "Match each motion story to the equation that omits the unneeded variable."
        ],
        "outcomes": [
          "suvat_selection_confusion",
          "constant_acceleration_condition_confusion",
          "motion_formula_story_confusion"
        ],
        "fields": [
          "equation_selection_checks",
          "missing_variable_checks",
          "constant_acceleration_checks",
          "story_matches"
        ],
        "depth": "number of motion stories correctly matched to an appropriate constant-acceleration equation"
      },
      "analogy_text": "The Quest-Log forecast board works only when the avatar keeps the same boost shift from beat to beat. Then the motion equations are summaries of a steady block of starting pace plus a triangular build of extra pace.",
      "commitment_prompt": "Before choosing an equation, decide whether the acceleration is constant and which variable the question does not need.",
      "micro_prompts": [
        {
          "prompt": "Compare equations by the variable they leave out.",
          "hint": "Each constant-acceleration equation is useful because one quantity is absent."
        },
        {
          "prompt": "Compare a uniform-acceleration story with a changing-acceleration story.",
          "hint": "One direct SUVAT step only works when the acceleration stays constant over the interval."
        }
      ],
      "diagnostic": [
        {
          "kind": "mcq",
          "id": "M1L4_D1",
          "prompt": "The standard equations of motion in this lesson can be used directly when...",
          "choices": [
            "the acceleration is constant",
            "the graph has any straight line",
            "the final speed is zero",
            "the journey starts from rest"
          ],
          "answer_index": 0,
          "hint": "These equations model constant-acceleration motion.",
          "tags": [
            "constant_acceleration_condition_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L4_D2",
          "prompt": "Which equation links u, v, a, and t but not s?",
          "choices": [
            "v = u + at",
            "s = ut + 0.5at^2",
            "v^2 = u^2 + 2as",
            "s = (u + v)t / 2"
          ],
          "answer_index": 0,
          "hint": "Choose the equation that omits displacement.",
          "tags": [
            "suvat_selection_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L4_D3",
          "prompt": "Which equation is most direct when u, v, and t are known and you want s?",
          "choices": [
            "s = (u + v)t / 2",
            "v = u + at",
            "v^2 = u^2 + 2as",
            "a = (v - u) / s"
          ],
          "answer_index": 0,
          "hint": "Choose the equation that uses the known quantities and omits the unknown you do not need.",
          "tags": [
            "suvat_selection_confusion",
            "motion_formula_story_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L4_D4",
          "prompt": "A car starts at 5 m/s and accelerates at 2 m/s^2 for 4 s. What final speed does it reach?",
          "accepted_answers": [
            "13 m/s",
            "13"
          ],
          "hint": "Use v = u + at.",
          "tags": [
            "suvat_selection_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L4_D5",
          "prompt": "Why is choosing the right equation better than memorizing a random formula first?",
          "choices": [
            "Because each equation matches a different constant-acceleration story and leaves out a different variable.",
            "Because every equation gives the same quantity in the same way.",
            "Because equations are only for rest cases.",
            "Because the longest equation is always safest."
          ],
          "answer_index": 0,
          "hint": "Equation choice should follow the motion story and missing variable.",
          "tags": [
            "motion_formula_story_confusion",
            "suvat_selection_confusion"
          ]
        }
      ],
      "inquiry": [
        {
          "prompt": "Pick two cases with different unknowns.",
          "hint": "Equation choice becomes easier when you first notice which variable is missing."
        },
        {
          "prompt": "Test a story where acceleration changes halfway through.",
          "hint": "A single constant-acceleration step is no longer safe for the whole interval."
        }
      ],
      "recon_prompts": [
        "Explain why the constant-acceleration condition matters before using SUVAT equations.",
        "Explain how the missing variable helps you choose a motion equation."
      ],
      "capsule_prompt": "Check the constant-acceleration condition first, then match the story to the equation that leaves out the unnecessary variable.",
      "capsule_checks": [
        {
          "kind": "mcq",
          "id": "M1L4_C1",
          "prompt": "If the acceleration changes during the interval, the safest statement is that...",
          "choices": [
            "one direct constant-acceleration equation cannot cover the whole interval without splitting it",
            "any SUVAT equation still works unchanged",
            "distance can no longer be found at all",
            "velocity and time stop being related"
          ],
          "answer_index": 0,
          "hint": "Changing acceleration breaks the single-rule assumption behind SUVAT.",
          "tags": [
            "constant_acceleration_condition_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L4_C2",
          "prompt": "A cyclist starts from rest and accelerates at 3 m/s^2 for 4 s. What final speed does the cyclist reach?",
          "accepted_answers": [
            "12 m/s",
            "12"
          ],
          "hint": "Use v = u + at with u = 0.",
          "tags": [
            "suvat_selection_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L4_C3",
          "prompt": "Which symbol stands for initial velocity in this lesson?",
          "choices": [
            "u",
            "v",
            "s",
            "a"
          ],
          "answer_index": 0,
          "hint": "Keep the motion symbols attached to the quantities they represent.",
          "tags": [
            "motion_formula_story_confusion"
          ]
        }
      ],
      "transfer": [
        {
          "kind": "mcq",
          "id": "M1L4_T1",
          "prompt": "A motion story gives u, a, and t and asks for v. Which equation is the best first choice?",
          "choices": [
            "v = u + at",
            "s = (u + v)t / 2",
            "v^2 = u^2 + 2as",
            "s = ut + 0.5at^2 because it is longer"
          ],
          "answer_index": 0,
          "hint": "Choose the equation that uses the known values and omits the quantity you do not need.",
          "tags": [
            "suvat_selection_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L4_T2",
          "prompt": "A trolley starts at 2 m/s and accelerates steadily at 3 m/s^2 for 5 s. What final speed does it reach?",
          "accepted_answers": [
            "17 m/s",
            "17"
          ],
          "hint": "Use v = u + at.",
          "tags": [
            "suvat_selection_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L4_T3",
          "prompt": "Which equation is most useful when time is not known but u, v, a, and s are linked?",
          "choices": [
            "v^2 = u^2 + 2as",
            "v = u + at",
            "s = (u + v)t / 2",
            "distance = speed x time"
          ],
          "answer_index": 0,
          "hint": "Use the constant-acceleration equation that omits time.",
          "tags": [
            "suvat_selection_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L4_T4",
          "prompt": "A cyclist speeds up for 3 s, coasts for 4 s, then brakes for 3 s. Why is one single constant-acceleration equation unsafe for the whole 10 s journey?",
          "choices": [
            "Because the acceleration is not constant across the whole story.",
            "Because time is too long for equations.",
            "Because coasting means zero distance.",
            "Because speed cannot change more than once."
          ],
          "answer_index": 0,
          "hint": "The motion must be split into intervals when the acceleration rule changes.",
          "tags": [
            "constant_acceleration_condition_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L4_T5",
          "prompt": "A train starts from rest and accelerates at 2 m/s^2 for 6 s. What distance does it travel in that time?",
          "accepted_answers": [
            "36 m",
            "36"
          ],
          "hint": "Use s = ut + 0.5at^2 with u = 0.",
          "tags": [
            "suvat_selection_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L4_T6",
          "prompt": "Why does s = (u + v)t / 2 work for constant acceleration?",
          "choices": [
            "Because average speed is halfway between u and v when speed changes uniformly.",
            "Because it ignores acceleration completely.",
            "Because it only works when u = 0.",
            "Because displacement always equals half of final speed times time."
          ],
          "answer_index": 0,
          "hint": "Uniform change makes the average of the endpoints meaningful.",
          "tags": [
            "motion_formula_story_confusion",
            "constant_acceleration_condition_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L4_T7",
          "prompt": "A learner uses v = u + at to find distance traveled. What is the main issue?",
          "choices": [
            "That equation gives final velocity, not displacement.",
            "That equation only works for negative acceleration.",
            "That equation always needs graph area instead.",
            "That equation is only for stationary objects."
          ],
          "answer_index": 0,
          "hint": "Choose equations by the quantity you need, not just by familiarity.",
          "tags": [
            "motion_formula_story_confusion",
            "suvat_selection_confusion"
          ]
        }
      ],
      "contract": {
        "concept_targets": [
          "Choose motion equations by matching the known quantities, unknown quantity, and constant-acceleration condition.",
          "Treat SUVAT equations as story-specific relationships rather than as interchangeable formulas."
        ],
        "prerequisite_lessons": [
          "M1_L2",
          "M1_L3"
        ],
        "misconception_focus": [
          "suvat_selection_confusion",
          "constant_acceleration_condition_confusion",
          "motion_formula_story_confusion"
        ],
        "formulas": [
          {
            "equation": "v = u + at",
            "meaning": "Final velocity equals initial velocity plus constant acceleration acting for time t.",
            "units": [
              "m/s"
            ],
            "conditions": "Use when acceleration is constant and displacement is not needed."
          },
          {
            "equation": "s = ut + 0.5at^2",
            "meaning": "Displacement grows from the initial motion plus the extra contribution from steady acceleration.",
            "units": [
              "m"
            ],
            "conditions": "Use when acceleration is constant and time is known."
          },
          {
            "equation": "s = (u + v)t / 2",
            "meaning": "For constant acceleration, average speed is the midpoint between u and v.",
            "units": [
              "m"
            ],
            "conditions": "Use when initial and final velocity are known over a constant-acceleration interval."
          },
          {
            "equation": "v^2 = u^2 + 2as",
            "meaning": "This constant-acceleration relationship links speeds and displacement without time.",
            "units": [
              "m^2/s^2"
            ],
            "conditions": "Use when acceleration is constant and time is not provided or not needed."
          }
        ],
        "representations": [
          {
            "kind": "words",
            "purpose": "Match each motion story to the correct equation and condition."
          },
          {
            "kind": "formula",
            "purpose": "Choose among the constant-acceleration equations deliberately."
          },
          {
            "kind": "table",
            "purpose": "Track which variable each equation omits."
          }
        ],
        "analogy_map": {
          "comparison": "The Quest-Log forecast board stands for the set of constant-acceleration equations.",
          "mapping": [
            "Each console screen stands for a different equation that leaves out one variable.",
            "The steady system setting stands for the constant-acceleration condition that must remain true before a prediction is valid."
          ],
          "limit": "The console analogy fails if the change rule itself keeps switching, because one constant rule cannot describe a mixed-acceleration journey in one step.",
          "prediction_prompt": "If the acceleration changes halfway through the journey, what should happen to your plan for equation choice?"
        },
        "worked_examples": [
          {
            "prompt": "A trolley starts at 3 m/s and accelerates steadily at 2 m/s^2 for 4 s. Find the final speed.",
            "steps": [
              "List the known quantities: u = 3 m/s, a = 2 m/s^2, t = 4 s.",
              "Notice that the unknown is v and displacement is unnecessary.",
              "Choose v = u + at and substitute to get v = 3 + 8."
            ],
            "final_answer": "11 m/s",
            "why_it_matters": "Equation choice becomes easier when the motion story and missing variable are clear first."
          },
          {
            "prompt": "A runner speeds up uniformly from 4 m/s to 10 m/s in 3 s. How far does the runner travel?",
            "steps": [
              "List the knowns and the unknown: u = 4 m/s, v = 10 m/s, t = 3 s, and the unknown is s.",
              "Choose the direct relation that uses those values: s = (u + v)t / 2.",
              "Substitute carefully: s = (4 + 10) x 3 / 2 = 14 x 3 / 2 = 21 m."
            ],
            "final_answer": "The runner travels 21 m.",
            "why_it_matters": "Good equation choice comes from the knowns, the unknown, and the constant-acceleration condition."
          }
        ],
        "visual_assets": [
          {
            "asset_id": "m1-l4-suvat.svg",
            "purpose": "Show a constant-acceleration decision grid that matches equations to the variable they omit.",
            "caption": "The forecast-console picture turns equation choice into a modeling decision instead of a memory game."
          }
        ],
        "simulation_contract": {
          "baseline_case": "Start with u = 2 m/s, a = 3 m/s^2, t = 4 s, and ask for v.",
          "comparison_tasks": [
            "Swap the unknown so time is absent instead.",
            "Compare a constant-acceleration story with a mixed-acceleration story."
          ],
          "watch_for": "Equation choice only becomes safe when the acceleration is constant and the missing variable is identified.",
          "takeaway": "SUVAT works as a set of story-matching tools, not as one formula used blindly."
        },
        "reflection_prompts": [
          "Explain why checking the constant-acceleration condition is part of the physics, not just a maths formality."
        ],
        "mastery_skills": [
          "Choose the correct constant-acceleration equation from a motion story.",
          "Use v = u + at and s = ut + 0.5at^2 accurately.",
          "Recognize when s = (u + v)t / 2 is justified.",
          "Identify when v^2 = u^2 + 2as is the natural choice.",
          "Reject direct SUVAT use when acceleration is not constant over the whole interval."
        ],
        "variation_plan": {
          "diagnostic": "Rotate constant-acceleration-condition, equation-selection, symbol, and light calculation prompts.",
          "concept_gate": "Swap between variable-omission reasoning, constant-acceleration judgment, and quick final-speed calculation.",
          "mastery": "Blend equation choice, condition checking, and mixed conceptual-numeric prompts without reusing the same stems."
        }
      }
    },
    {
      "id": "M1_L5",
      "title": "Gradient Interpretation Across Motion Graphs",
      "sim": {
        "lab_id": "m1_gradient_context_lab",
        "title": "Gradient meaning explorer",
        "description": "Lay the same tilt across a progress log and a pace log so students learn that slope meaning comes from the axes, not from steepness alone.",
        "instructions": [
          "Place the same tilt on a distance-time screen and a speed-time screen.",
          "Compare a high but shallow graph segment with a low but steep one.",
          "Build one zero-gradient case on each graph type and compare the motion meaning."
        ],
        "outcomes": [
          "graph_gradient_context_confusion",
          "graph_height_vs_gradient_confusion",
          "multi_representation_motion_confusion"
        ],
        "fields": [
          "graph_type_switches",
          "same_tilt_comparisons",
          "zero_gradient_checks",
          "meaning_explanations"
        ],
        "depth": "number of cross-graph comparisons that correctly explain what the same gradient means on each graph type"
      },
      "analogy_text": "Quest-Log uses two logs: the progress log and the pace log. The same slope gauge can sit on both, but the axes decide the meaning. On the progress log it reads pace; on the pace log it reads boost shift.",
      "commitment_prompt": "Before you interpret a slope, say which graph the slope belongs to and what the axes represent.",
      "micro_prompts": [
        {
          "prompt": "Compare the same numerical tilt on two graph types.",
          "hint": "Gradient meaning comes from the axes, not from steepness alone."
        },
        {
          "prompt": "Compare zero gradient on a distance-time graph with zero gradient on a speed-time graph.",
          "hint": "Zero gradient means stopped on one graph and constant speed on the other."
        }
      ],
      "diagnostic": [
        {
          "kind": "mcq",
          "id": "M1L5_D1",
          "prompt": "On a distance-time graph, the gradient represents...",
          "choices": [
            "speed",
            "distance",
            "acceleration",
            "time"
          ],
          "answer_index": 0,
          "hint": "Distance-time gradient tells how quickly distance changes.",
          "tags": [
            "graph_gradient_context_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L5_D2",
          "prompt": "On a speed-time graph, the gradient represents...",
          "choices": [
            "acceleration",
            "speed",
            "distance",
            "momentum"
          ],
          "answer_index": 0,
          "hint": "Speed-time gradient tells how quickly speed changes.",
          "tags": [
            "graph_gradient_context_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L5_D3",
          "prompt": "Why can the same numerical gradient mean different things on different motion graphs?",
          "choices": [
            "Because the axes are different, so rise/run compares different physical quantities.",
            "Because gradient changes color between graphs.",
            "Because only curved lines have meaning.",
            "Because speed and acceleration are the same quantity."
          ],
          "answer_index": 0,
          "hint": "Always read the axes before interpreting a slope.",
          "tags": [
            "graph_gradient_context_confusion",
            "multi_representation_motion_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L5_D4",
          "prompt": "A distance-time graph rises by 30 m in 6 s. What speed does its gradient show?",
          "accepted_answers": [
            "5 m/s",
            "5"
          ],
          "hint": "Use the distance-time gradient as speed.",
          "tags": [
            "graph_gradient_context_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L5_D5",
          "prompt": "A horizontal line on a speed-time graph has zero gradient, so it shows...",
          "choices": [
            "zero acceleration even if the speed is not zero",
            "zero distance only",
            "the object must be stopped",
            "reverse motion"
          ],
          "answer_index": 0,
          "hint": "Zero gradient on a speed-time graph means the speed is constant.",
          "tags": [
            "graph_gradient_context_confusion"
          ]
        }
      ],
      "inquiry": [
        {
          "prompt": "Hold the tilt fixed and swap the graph type.",
          "hint": "The same steepness can represent speed on one graph and acceleration on another."
        },
        {
          "prompt": "Compare high-but-shallow with low-but-steep segments.",
          "hint": "Height and slope still do different jobs on both graph types."
        }
      ],
      "recon_prompts": [
        "Explain why you must name the graph type before saying what a gradient means.",
        "Explain why a zero gradient does not tell the same motion story on every motion graph."
      ],
      "capsule_prompt": "Name the graph, read the axes, then translate the slope into the matching motion quantity.",
      "capsule_checks": [
        {
          "kind": "mcq",
          "id": "M1L5_C1",
          "prompt": "Why can you not say steeper always means faster without naming the graph?",
          "choices": [
            "Because steeper can mean greater speed on a distance-time graph but greater acceleration on a speed-time graph.",
            "Because steepness has no physical meaning.",
            "Because all graphs use area instead of slope.",
            "Because faster motion always gives a flatter line."
          ],
          "answer_index": 0,
          "hint": "Graph type decides what the gradient is comparing.",
          "tags": [
            "graph_gradient_context_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L5_C2",
          "prompt": "A speed-time graph rises from 4 m/s to 10 m/s in 3 s. What acceleration does its gradient show?",
          "accepted_answers": [
            "2 m/s^2",
            "2"
          ],
          "hint": "Use change in speed divided by time.",
          "tags": [
            "graph_gradient_context_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L5_C3",
          "prompt": "Two distance-time segments are at different heights but have the same gradient. What is the same?",
          "choices": [
            "their speed",
            "their distance from the start",
            "their total time",
            "their acceleration"
          ],
          "answer_index": 0,
          "hint": "Equal distance-time gradient means equal speed.",
          "tags": [
            "graph_height_vs_gradient_confusion",
            "graph_gradient_context_confusion"
          ]
        }
      ],
      "transfer": [
        {
          "kind": "mcq",
          "id": "M1L5_T1",
          "prompt": "Which pair correctly matches graph type and gradient meaning?",
          "choices": [
            "distance-time -> speed, speed-time -> acceleration",
            "distance-time -> acceleration, speed-time -> speed",
            "distance-time -> distance, speed-time -> time",
            "distance-time -> area, speed-time -> direction"
          ],
          "answer_index": 0,
          "hint": "Always connect the gradient to the variables on the axes.",
          "tags": [
            "graph_gradient_context_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L5_T2",
          "prompt": "A speed-time graph is steeply rising but currently low on the graph. Which statement is best?",
          "choices": [
            "The current speed is still low, but the acceleration is large.",
            "The current speed is large because the line is steep.",
            "Distance is large because the line is low.",
            "The object is stopped because the line begins near zero."
          ],
          "answer_index": 0,
          "hint": "Height and slope answer different questions on the speed-time graph.",
          "tags": [
            "graph_height_vs_gradient_confusion",
            "graph_gradient_context_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L5_T3",
          "prompt": "A distance-time graph is high on the page but not steep. Which statement is best?",
          "choices": [
            "The object is far into the journey but moving slowly at that stage.",
            "The object is accelerating strongly.",
            "The object is moving faster than any lower line.",
            "The object must be stopped because the graph is high."
          ],
          "answer_index": 0,
          "hint": "Graph height tells recorded distance while slope tells speed.",
          "tags": [
            "graph_height_vs_gradient_confusion",
            "graph_gradient_context_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L5_T4",
          "prompt": "A distance-time segment rises by 24 m in 8 s. What speed does it show?",
          "accepted_answers": [
            "3 m/s",
            "3"
          ],
          "hint": "Use rise over run for the distance-time segment.",
          "tags": [
            "graph_gradient_context_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L5_T5",
          "prompt": "Why does zero gradient not tell the same motion story on every motion graph?",
          "choices": [
            "Because zero gradient means no distance change on a distance-time graph but no speed change on a speed-time graph.",
            "Because zero gradient always means reverse motion.",
            "Because zero gradient always means the journey ended.",
            "Because gradient is only meaningful on curved graphs."
          ],
          "answer_index": 0,
          "hint": "The axes decide what the zero slope is telling you.",
          "tags": [
            "graph_gradient_context_confusion",
            "multi_representation_motion_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L5_T6",
          "prompt": "Two speed-time graphs have the same positive gradient but different starting heights. What is the same?",
          "choices": [
            "their acceleration",
            "their speed at every moment",
            "their total distance for every interval",
            "their motion direction"
          ],
          "answer_index": 0,
          "hint": "Equal speed-time gradient means equal acceleration.",
          "tags": [
            "graph_gradient_context_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L5_T7",
          "prompt": "In the slope-gauge analogy, changing the screen while keeping the same tilt represents...",
          "choices": [
            "keeping the mathematical gradient style the same while changing the physics meaning because the axes changed",
            "making the journey longer automatically",
            "turning speed into distance without changing units",
            "proving that all motion graphs tell the same story"
          ],
          "answer_index": 0,
          "hint": "The same mathematical operation can describe different quantities when the axes differ.",
          "tags": [
            "multi_representation_motion_confusion",
            "graph_gradient_context_confusion"
          ]
        }
      ],
      "contract": {
        "concept_targets": [
          "Interpret gradient contextually by first identifying the motion graph type and its axes.",
          "Explain why height and gradient must not be confused on either distance-time or speed-time graphs."
        ],
        "prerequisite_lessons": [
          "M1_L1",
          "M1_L2",
          "M1_L3"
        ],
        "misconception_focus": [
          "graph_gradient_context_confusion",
          "graph_height_vs_gradient_confusion",
          "multi_representation_motion_confusion"
        ],
        "formulas": [
          {
            "equation": "gradient = rise / run",
            "meaning": "Graph slope compares vertical change with horizontal change.",
            "units": [
              "depends on axes"
            ],
            "conditions": "Always read the axes before attaching physical meaning."
          },
          {
            "equation": "distance-time gradient = change in distance / change in time",
            "meaning": "On a distance-time graph, slope tells speed.",
            "units": [
              "m/s"
            ],
            "conditions": "Use for straight or locally straight distance-time segments."
          },
          {
            "equation": "speed-time gradient = change in speed / change in time",
            "meaning": "On a speed-time graph, slope tells acceleration.",
            "units": [
              "m/s^2"
            ],
            "conditions": "Use for straight or locally straight speed-time segments."
          }
        ],
        "representations": [
          {
            "kind": "words",
            "purpose": "Compare what the same slope means on two graph types."
          },
          {
            "kind": "formula",
            "purpose": "Use rise/run with graph-specific axes."
          },
          {
            "kind": "graph",
            "purpose": "Read distance-time and speed-time slopes side by side."
          }
        ],
        "analogy_map": {
          "comparison": "One slope gauge laid over different Quest-Log screens stands for gradient interpretation across graph types.",
          "mapping": [
            "The same tilt stands for the same mathematical idea of rise/run.",
            "The screen beneath it stands for the graph axes that decide whether the tilt means speed or acceleration."
          ],
          "limit": "The same visual steepness does not guarantee the same physical quantity; you must inspect the graph axes before interpreting the slope.",
          "prediction_prompt": "If the same tilt is placed on a progress log and then on a pace log, what two different motion meanings should appear?"
        },
        "worked_examples": [
          {
            "prompt": "A distance-time graph rises from 4 m to 16 m in 6 s, while a speed-time graph rises from 3 m/s to 9 m/s in 3 s. What does each gradient mean?",
            "steps": [
              "For the distance-time graph, calculate the gradient: (16 - 4) / 6 = 2 m/s, so that slope represents speed.",
              "For the speed-time graph, calculate the gradient: (9 - 3) / 3 = 2 m/s^2, so that slope represents acceleration.",
              "The number 2 appears in both calculations, but the axes change the physical meaning and the unit."
            ],
            "final_answer": "The first gradient is a speed of 2 m/s, and the second gradient is an acceleration of 2 m/s^2.",
            "why_it_matters": "This makes students name the axes before naming the slope."
          },
          {
            "prompt": "A distance-time segment rises 15 m in 5 s. A speed-time segment rises from 2 m/s to 8 m/s in 2 s. What does each slope tell you?",
            "steps": [
              "On the distance-time graph, use slope = distance change / time change: 15 / 5 = 3 m/s.",
              "On the speed-time graph, use slope = speed change / time change: (8 - 2) / 2 = 3 m/s^2.",
              "The same numerical slope can name different quantities because the axes are different."
            ],
            "final_answer": "The distance-time graph shows 3 m/s, while the speed-time graph shows 3 m/s^2.",
            "why_it_matters": "This protects students from saying steeper always means faster without naming the graph."
          }
        ],
        "visual_assets": [
          {
            "asset_id": "m1-l5-gradient.svg",
            "purpose": "Show the same tilt placed on a distance-time graph and a speed-time graph with different meaning labels.",
            "caption": "The slope-gauge picture makes graph context decide what gradient means."
          }
        ],
        "simulation_contract": {
          "baseline_case": "Start with a distance-time segment of 12 m in 4 s and a speed-time segment of 4 m/s to 12 m/s in 4 s.",
          "comparison_tasks": [
            "Keep the tilt the same and swap the graph type.",
            "Compare zero gradient on both graph types."
          ],
          "watch_for": "Gradient meaning comes from the axes, so graph type must be named before the slope is interpreted.",
          "takeaway": "The same steepness can represent different motion quantities on different graphs."
        },
        "reflection_prompts": [
          "Explain why saying the graph is steeper is not yet a full physics explanation until the graph type is named."
        ],
        "mastery_skills": [
          "Identify gradient meaning on a distance-time graph.",
          "Identify gradient meaning on a speed-time graph.",
          "Explain why the same slope can mean different things across graphs.",
          "Separate graph height from graph gradient on both graph types.",
          "Interpret zero gradient contextually across graph types."
        ],
        "variation_plan": {
          "diagnostic": "Rotate graph-type-to-gradient matches, same-gradient-different-meaning checks, and zero-gradient prompts.",
          "concept_gate": "Swap between cross-graph comparisons, quick gradient calculations, and same-height-vs-same-slope reasoning.",
          "mastery": "Blend graph-context explanation, slope calculation, and misconception rejection without repeating the same stem pattern."
        }
      }
    },
    {
      "id": "M1_L6",
      "title": "Area Interpretation and Motion Synthesis",
      "sim": {
        "lab_id": "m1_area_motion_synthesis_lab",
        "title": "Area and motion synthesis explorer",
        "description": "Use the Quest-Log pace log as accumulated progress strips so area becomes total distance, not just a shape under a graph.",
        "instructions": [
          "Create one rectangular area, one triangular area, and one mixed journey with both.",
          "Compare two different speed-time graphs that have the same total area.",
          "Explain why area under a distance-time graph does not answer the same question."
        ],
        "outcomes": [
          "area_under_graph_confusion",
          "graph_gradient_context_confusion",
          "multi_representation_motion_confusion"
        ],
        "fields": [
          "rectangle_area_cases",
          "triangle_area_cases",
          "same_area_different_story_cases",
          "representation_matches"
        ],
        "depth": "number of speed-time graph areas correctly turned into distance and matched back to a motion story"
      },
      "analogy_text": "In Quest-Log, every strip under the pace log is progress earned during one beat of the mission clock. Add the strips and you get the total progress, so the whole shaded area under a speed-time graph becomes distance traveled.",
      "commitment_prompt": "Before you calculate, decide whether the graph question is asking for a slope meaning or an area meaning.",
      "micro_prompts": [
        {
          "prompt": "Compare a tall narrow area with a lower wider area.",
          "hint": "Different speed patterns can still build the same total area and therefore the same total distance."
        },
        {
          "prompt": "Compare area under a speed-time graph with area under a distance-time graph.",
          "hint": "Area under the speed-time graph represents distance because of the axes; that rule does not transfer automatically to every graph."
        }
      ],
      "diagnostic": [
        {
          "kind": "mcq",
          "id": "M1L6_D1",
          "prompt": "The area under a speed-time graph represents...",
          "choices": [
            "distance traveled",
            "acceleration",
            "final speed only",
            "the graph gradient"
          ],
          "answer_index": 0,
          "hint": "On a speed-time graph, area combines speed with time to give distance.",
          "tags": [
            "area_under_graph_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L6_D2",
          "prompt": "A flat speed-time section at 5 m/s lasting 4 s covers a distance of...",
          "choices": [
            "20 m",
            "9 m",
            "5 m",
            "1.25 m"
          ],
          "answer_index": 0,
          "hint": "Use the rectangle area: speed x time.",
          "tags": [
            "area_under_graph_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L6_D3",
          "prompt": "A triangular area under a speed-time graph still represents distance because...",
          "choices": [
            "it still combines speed with time across the interval",
            "all triangles automatically mean acceleration only",
            "area never depends on axes",
            "triangles only show direction changes"
          ],
          "answer_index": 0,
          "hint": "The graph axes still make the area a distance quantity.",
          "tags": [
            "area_under_graph_confusion",
            "graph_gradient_context_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L6_D4",
          "prompt": "A speed rises uniformly from 0 m/s to 10 m/s in 4 s. What distance is traveled in that interval?",
          "accepted_answers": [
            "20 m",
            "20"
          ],
          "hint": "Use the triangle area rule: 0.5 x base x height, with time as the base and speed as the height.",
          "tags": [
            "area_under_graph_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L6_D5",
          "prompt": "Why does area under a distance-time graph not answer the same motion question?",
          "choices": [
            "Because the axes are different, so the area is not the total distance traveled quantity.",
            "Because distance-time graphs have no area.",
            "Because only curved graphs can have area.",
            "Because distance-time graph area always means acceleration."
          ],
          "answer_index": 0,
          "hint": "Area meaning depends on the graph axes, not on the word graph alone.",
          "tags": [
            "graph_gradient_context_confusion",
            "area_under_graph_confusion"
          ]
        }
      ],
      "inquiry": [
        {
          "prompt": "Build one rectangle and one triangle under a speed-time graph.",
          "hint": "Simple shape areas can be added to get the total distance."
        },
        {
          "prompt": "Design two different graphs with the same total area.",
          "hint": "The speed story can differ even when the total distance is the same."
        }
      ],
      "recon_prompts": [
        "Explain why area under a speed-time graph gives distance traveled.",
        "Explain how two different speed-time graphs can represent the same total distance."
      ],
      "capsule_prompt": "Split the speed-time area into simple shapes, add them, and keep the graph axes in mind while interpreting the result.",
      "capsule_checks": [
        {
          "kind": "mcq",
          "id": "M1L6_C1",
          "prompt": "A trapezium under a speed-time graph is often handled by...",
          "choices": [
            "splitting it into simpler shapes such as a rectangle and a triangle",
            "treating it as a gradient only",
            "ignoring the sloping part",
            "using the final speed as the total distance"
          ],
          "answer_index": 0,
          "hint": "Complex graph areas become manageable when split into simple shapes.",
          "tags": [
            "area_under_graph_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L6_C2",
          "prompt": "A flat speed-time section at 8 m/s lasts 3 s. What distance does it add?",
          "accepted_answers": [
            "24 m",
            "24"
          ],
          "hint": "Use speed x time for the rectangular area.",
          "tags": [
            "area_under_graph_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L6_C3",
          "prompt": "Two different speed-time graphs have the same total area. What must be the same?",
          "choices": [
            "the total distance traveled",
            "the acceleration at every instant",
            "the final speed",
            "the exact graph shape"
          ],
          "answer_index": 0,
          "hint": "Equal area under a speed-time graph means equal total distance.",
          "tags": [
            "area_under_graph_confusion",
            "multi_representation_motion_confusion"
          ]
        }
      ],
      "transfer": [
        {
          "kind": "mcq",
          "id": "M1L6_T1",
          "prompt": "One speed-time graph is tall and narrow, and another is low and wide, but the areas are equal. What is true?",
          "choices": [
            "They represent the same total distance with different speed patterns.",
            "They represent the same acceleration at every instant.",
            "They must finish at the same speed.",
            "They must have the same gradient everywhere."
          ],
          "answer_index": 0,
          "hint": "Equal speed-time area means equal total distance, not identical motion in every detail.",
          "tags": [
            "area_under_graph_confusion",
            "multi_representation_motion_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L6_T2",
          "prompt": "A runner moves at 6 m/s for 5 s. What distance is traveled?",
          "accepted_answers": [
            "30 m",
            "30"
          ],
          "hint": "Use rectangle area or speed x time.",
          "tags": [
            "area_under_graph_confusion"
          ]
        },
        {
          "kind": "short",
          "id": "M1L6_T3",
          "prompt": "A speed rises uniformly from 4 m/s to 12 m/s over 2 s. What distance is traveled in that interval?",
          "accepted_answers": [
            "16 m",
            "16"
          ],
          "hint": "Use average speed x time or the trapezium area.",
          "tags": [
            "area_under_graph_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L6_T4",
          "prompt": "Why does splitting a speed-time graph area into simple shapes help?",
          "choices": [
            "Each shape contributes part of the total distance, so the parts can be added consistently.",
            "Each shape removes the need for units.",
            "Only rectangles represent motion meaningfully.",
            "It turns every graph into a gradient question."
          ],
          "answer_index": 0,
          "hint": "Area can be accumulated piece by piece because distance adds.",
          "tags": [
            "area_under_graph_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L6_T5",
          "prompt": "A learner reads the final graph height as the total distance traveled. What is the best correction?",
          "choices": [
            "The final height is the final speed; distance comes from the whole area under the graph.",
            "The final height is the total distance whenever the graph is flat.",
            "Distance comes only from the graph width.",
            "Height and area always mean the same thing on motion graphs."
          ],
          "answer_index": 0,
          "hint": "On a speed-time graph, height is speed and area is distance.",
          "tags": [
            "area_under_graph_confusion",
            "graph_height_vs_gradient_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L6_T6",
          "prompt": "Which method best finds distance on a graph with one constant-speed section followed by steady speeding up?",
          "choices": [
            "Add the rectangle area and the triangle area.",
            "Use only the final speed.",
            "Multiply the first speed by the full time and ignore the rest.",
            "Find the gradient and call it the distance."
          ],
          "answer_index": 0,
          "hint": "Mixed journeys need the areas from all sections added together.",
          "tags": [
            "area_under_graph_confusion"
          ]
        },
        {
          "kind": "mcq",
          "id": "M1L6_T7",
          "prompt": "When a motion story is shown as words, equation, and graph, what should stay consistent across all three?",
          "choices": [
            "the same times, speed changes, and total distances",
            "the same line color",
            "the same graph height and area meaning on every graph type",
            "only the final number"
          ],
          "answer_index": 0,
          "hint": "A good motion model says the same physical story in every representation.",
          "tags": [
            "multi_representation_motion_confusion"
          ]
        }
      ],
      "contract": {
        "concept_targets": [
          "Interpret area under a speed-time graph as total distance traveled.",
          "Synthesize motion stories by combining graph area, shape, and other representations consistently."
        ],
        "prerequisite_lessons": [
          "M1_L2",
          "M1_L4",
          "M1_L5"
        ],
        "misconception_focus": [
          "area_under_graph_confusion",
          "graph_gradient_context_confusion",
          "multi_representation_motion_confusion"
        ],
        "formulas": [
          {
            "equation": "distance from a flat speed-time section = speed x time",
            "meaning": "A rectangular area under a speed-time graph gives the distance for a constant-speed interval.",
            "units": [
              "m"
            ],
            "conditions": "Use on horizontal speed-time sections."
          },
          {
            "equation": "triangle area = 0.5 x base x height",
            "meaning": "A triangular speed-time area gives the distance for a speed changing linearly from zero or from a baseline after decomposition.",
            "units": [
              "m"
            ],
            "conditions": "Use after identifying time as the base and speed as the height."
          },
          {
            "equation": "distance under constant acceleration = average speed x time = (u + v)t / 2",
            "meaning": "For a trapezium under a speed-time graph, the area matches average speed multiplied by time.",
            "units": [
              "m"
            ],
            "conditions": "Use when speed changes uniformly over the interval."
          }
        ],
        "representations": [
          {
            "kind": "words",
            "purpose": "Tell the motion story in terms of total distance built across intervals."
          },
          {
            "kind": "formula",
            "purpose": "Calculate total distance from simple graph areas or average speed."
          },
          {
            "kind": "graph",
            "purpose": "Read rectangular, triangular, and trapezium areas under a speed-time graph."
          }
        ],
        "analogy_map": {
          "comparison": "The shaded region under the Quest-Log pace log stands for accumulated distance traveled.",
          "mapping": [
            "Tile height stands for speed and tile width stands for time.",
            "The total filled area stands for the total distance built across the whole motion interval."
          ],
          "limit": "Area meaning comes from the speed-time axes, so the same area rule does not transfer unchanged to a distance-time graph.",
          "prediction_prompt": "If two different speed-time graphs fill the same total area, what should be true about the distance traveled?"
        },
        "worked_examples": [
          {
            "prompt": "A speed-time graph shows 6 m/s for 4 s and then a straight rise from 6 m/s to 10 m/s over the next 2 s. Find the total distance.",
            "steps": [
              "Calculate the rectangle first: 6 x 4 = 24 m.",
              "Treat the second part as a trapezium or as average speed x time: (6 + 10) / 2 x 2 = 16 m.",
              "Add the sections to get the whole distance."
            ],
            "final_answer": "40 m",
            "why_it_matters": "Motion synthesis requires adding the distance built in each section instead of looking only at one graph feature."
          },
          {
            "prompt": "Graph A is a rectangle at 8 m/s for 5 s. Graph B is a triangle that rises from 0 m/s to 16 m/s over the same 5 s. Which journey covers more distance?",
            "steps": [
              "Find the area of Graph A: rectangle area = 8 x 5 = 40 m.",
              "Find the area of Graph B: triangle area = 1/2 x 5 x 16 = 40 m.",
              "Equal areas under speed-time graphs mean equal distances traveled."
            ],
            "final_answer": "They cover the same distance: 40 m each.",
            "why_it_matters": "Different graph shapes can represent the same total distance if the areas match."
          }
        ],
        "visual_assets": [
          {
            "asset_id": "m1-l6-area.svg",
            "purpose": "Show shaded strips, rectangle-plus-triangle decomposition, and a same-area comparison within the Quest-Log world.",
            "caption": "The accumulator picture makes total distance feel like built area rather than a guessed number."
          }
        ],
        "simulation_contract": {
          "baseline_case": "Start with a flat 5 m/s section for 4 s, then add a rising section to 10 m/s over 4 s.",
          "comparison_tasks": [
            "Compare two different graphs with the same total area.",
            "Split a mixed graph into rectangle and triangle sections."
          ],
          "watch_for": "Area under a speed-time graph gives distance only because the axes are speed and time.",
          "takeaway": "Total distance comes from the whole area under the speed-time graph, and different speed stories can still build the same area."
        },
        "reflection_prompts": [
          "Explain how two different speed-time graphs can represent the same total distance without representing the same motion at every moment."
        ],
        "mastery_skills": [
          "Find distance from rectangular and triangular speed-time areas.",
          "Use average speed for uniformly changing-speed intervals.",
          "Explain why equal areas can describe equal total distance with different motion stories.",
          "Reject height-as-distance readings on speed-time graphs.",
          "Keep words, equations, and graphs consistent in one motion synthesis task."
        ],
        "variation_plan": {
          "diagnostic": "Rotate area-meaning, rectangle-area, triangle-area, and graph-type contrast prompts.",
          "concept_gate": "Swap between simple section-area calculation, same-area-different-story judgment, and graph-type explanation.",
          "mastery": "Blend area calculation, misconception checks, and representation-synthesis prompts without reusing the same stem structure."
        }
      }
    }
  ]
}''')


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_project_id(cli_project: str | None) -> str:
    return cli_project or os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT") or os.getenv("GCLOUD_PROJECT") or "apip-dev-487809-c949c"


def init_firebase(project_id: str):
    if firebase_admin is None or credentials is None or firestore is None:
        raise RuntimeError(
            "firebase_admin and google-cloud-firestore are required for --apply runs."
        )
    if not firebase_admin._apps:
        firebase_admin.initialize_app(credentials.ApplicationDefault(), {"projectId": project_id})
    return firestore.Client(project=project_id)


def upsert_doc(db, collection: str, doc_id: str, data: Dict[str, Any], apply: bool) -> None:
    if apply:
        if db is None:
            raise RuntimeError("Firestore client is required for apply mode.")
        ref = db.collection(collection).document(doc_id)
        ref.set(data, merge=True)
        print(f"UPSERT {collection}/{doc_id}")
    else:
        print(f"[DRY] UPSERT {collection}/{doc_id}")


def print_preview(title: str, items: List[Tuple[str, str]]) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)
    for collection, doc_id in items:
        print(f"- {collection}/{doc_id}")
    print("=" * 72 + "\n")


def safe_tags(tags: List[str]) -> List[str]:
    return [tag for tag in tags if tag in M1_ALLOWLIST]


def make_mcq(qid: str, prompt: str, choices: List[str], answer_index: int, hint: str, tags: List[str]) -> Dict[str, Any]:
    feedback = [hint for _ in choices]
    if 0 <= answer_index < len(feedback):
        feedback[answer_index] = hint
    return {"id": qid, "question_id": qid, "type": "mcq", "prompt": prompt, "choices": choices, "answer_index": answer_index, "hint": hint, "feedback": feedback, "misconception_tags": safe_tags(tags)}


def make_short(qid: str, prompt: str, accepted_answers: List[str], hint: str, tags: List[str]) -> Dict[str, Any]:
    return {"id": qid, "question_id": qid, "type": "short", "prompt": prompt, "accepted_answers": accepted_answers, "hint": hint, "feedback": [hint], "misconception_tags": safe_tags(tags)}


def prompt_block(prompt: str, hint: str) -> Dict[str, Any]:
    return {"prompt": prompt, "hint": hint}


def formula(eq: str, meaning: str, units: List[str], conditions: str) -> Dict[str, Any]:
    return {"equation": eq, "meaning": meaning, "units": units, "conditions": conditions}


def rep(kind: str, purpose: str) -> Dict[str, Any]:
    return {"kind": kind, "purpose": purpose}


def example(prompt: str, steps: List[str], final_answer: str, why: str, answer_reason: str = "") -> Dict[str, Any]:
    payload = {"prompt": prompt, "steps": steps, "final_answer": final_answer, "why_it_matters": why}
    if answer_reason:
        payload["answer_reason"] = answer_reason
    return payload


def vis(
    asset_id: str,
    purpose: str,
    caption: str,
    *,
    concept: str = "",
    title: str = "",
    phase_key: str = "analogical_grounding",
    template: str = "auto",
    meta: Dict[str, Any] | None = None,
    width: int = 1280,
    height: int = 720,
) -> Dict[str, Any]:
    return {
        "asset_id": asset_id,
        "purpose": purpose,
        "caption": caption,
        "concept": concept,
        "title": title,
        "phase_key": phase_key,
        "template": template,
        "meta": dict(meta or {}),
        "width": width,
        "height": height,
    }


def anim(
    asset_id: str,
    concept: str,
    title: str,
    description: str,
    *,
    phase_key: str = "analogical_grounding",
    duration_sec: int = 8,
) -> Dict[str, Any]:
    return {
        "asset_id": asset_id,
        "concept": concept,
        "title": title,
        "description": description,
        "phase_key": phase_key,
        "duration_sec": duration_sec,
    }


def assessment_targets(diagnostic_pool_min: int, concept_gate_pool_min: int, mastery_pool_min: int) -> Dict[str, Any]:
    return {
        "diagnostic_pool_min": diagnostic_pool_min,
        "concept_gate_pool_min": concept_gate_pool_min,
        "mastery_pool_min": mastery_pool_min,
        "fresh_attempt_policy": (
            "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem."
        ),
    }


def spec_mcq(qid: str, prompt: str, choices: List[str], answer_index: int, hint: str, tags: List[str]) -> Dict[str, Any]:
    return {
        "kind": "mcq",
        "id": qid,
        "prompt": prompt,
        "choices": choices,
        "answer_index": answer_index,
        "hint": hint,
        "tags": tags,
    }


def spec_short(qid: str, prompt: str, accepted_answers: List[str], hint: str, tags: List[str]) -> Dict[str, Any]:
    return {
        "kind": "short",
        "id": qid,
        "prompt": prompt,
        "accepted_answers": accepted_answers,
        "hint": hint,
        "tags": tags,
    }


def apply_m1_enhancements() -> None:
    M1_SPEC["module_description"] = (
        "Module 1 treats kinematics as a representation system: journeys, graphs, signed rates, "
        "constant-acceleration forecasts, gradient context, and area reasoning must stay aligned "
        "without collapsing into basic motion slogans."
    )
    M1_SPEC["mastery_outcomes"] = [
        "Interpret distance-time and speed-time graphs as recorded motion stories rather than as pictures of the route.",
        "Keep graph height, gradient, and area conceptually separate and justify each from the graph axes.",
        "Interpret acceleration as a signed rate of velocity change and reason about sign without relying on everyday intuition alone.",
        "Choose constant-acceleration equations from the knowns, the unknown, and the constant-acceleration condition.",
        "Translate confidently between motion stories, graphs, equations, and quantitative calculations.",
        "Use graph reasoning to compare different motion histories that can still share the same final distance, speed, or shaded area.",
    ]

    lessons = {str(lesson["id"]): lesson for lesson in M1_SPEC["lessons"]}
    lesson_concepts = {
        "M1_L1": "distance_time_story",
        "M1_L2": "speed_time_change",
        "M1_L3": "signed_acceleration",
        "M1_L4": "constant_acceleration_forecast",
        "M1_L5": "graph_gradient_context",
        "M1_L6": "speed_time_area",
    }
    lesson_titles = {
        "M1_L1": "Distance-Time Story Board",
        "M1_L2": "Pace Log Reasoning Board",
        "M1_L3": "Signed Velocity and Acceleration Board",
        "M1_L4": "Constant-Acceleration Forecast Board",
        "M1_L5": "Gradient Meaning Comparator",
        "M1_L6": "Area-to-Distance Builder",
    }
    lesson_visual_assets = {
        "M1_L1": [
            vis(
                "m1_l1_distance_time_graph",
                "Show a distance-time graph with a pause and a faster section so the graph is clearly a record of motion rather than a map of the path.",
                "Distance-time graph: slope gives speed and flat sections show no motion.",
                concept="distance_time_story",
                title="Distance-Time Story Board",
                template="physics_graph",
                meta={
                    "graph_type": "generic_xy",
                    "title": "Distance-Time Story Board",
                    "subtitle": "The graph records the journey. It is not the route shape itself.",
                    "x_label": "Time (s)",
                    "y_label": "Distance from start (m)",
                    "show_legend": False,
                    "x_min": 0,
                    "x_max": 8,
                    "y_min": 0,
                    "y_max": 24,
                    "series": [
                        {
                            "label": "Journey log",
                            "points": [[0, 0], [2, 6], [4, 6], [6, 18], [8, 24]],
                        }
                    ],
                    "annotations": [
                        {"x": 3.1, "y": 7.8, "text": "flat = stopped", "color": "#fde68a"},
                        {"x": 6.1, "y": 20.0, "text": "steeper = faster", "color": "#86efac", "anchor": "start"},
                    ],
                },
            )
        ],
        "M1_L2": [
            vis(
                "m1_l2_speed_time_graph",
                "Show a speed-time graph where graph height gives speed now and slope shows whether the speed is changing.",
                "Speed-time graph: height gives speed, slope gives acceleration.",
                concept="speed_time_change",
                title="Pace Log Reasoning Board",
                template="physics_graph",
                meta={
                    "graph_type": "kinematics_time_series",
                    "title": "Pace Log Reasoning Board",
                    "subtitle": "Height answers speed now. Tilt answers how quickly speed changes.",
                    "x_label": "Time (s)",
                    "y_label": "Speed (m/s)",
                    "show_legend": False,
                    "x_min": 0,
                    "x_max": 8,
                    "y_min": 0,
                    "y_max": 12,
                    "series": [
                        {
                            "label": "Speed log",
                            "points": [[0, 4], [2, 4], [4, 10], [6, 10], [8, 6]],
                        }
                    ],
                    "annotations": [
                        {"x": 1.5, "y": 5.3, "text": "flat = constant speed", "color": "#fde68a"},
                        {"x": 4.3, "y": 9.8, "text": "rising slope = speeding up", "color": "#86efac", "anchor": "start"},
                    ],
                },
            )
        ],
        "M1_L3": [
            vis(
                "m1_l3_signed_acceleration_graph",
                "Show a velocity-time graph crossing the axis so learners can separate the sign of velocity from the sign of acceleration.",
                "Velocity-time graph: positive slope can act on motion below or above the axis.",
                concept="signed_acceleration",
                title="Signed Velocity and Acceleration Board",
                template="physics_graph",
                meta={
                    "graph_type": "kinematics_time_series",
                    "title": "Signed Velocity and Acceleration Board",
                    "subtitle": "Velocity sign comes from the axis. Acceleration sign comes from the slope.",
                    "x_label": "Time (s)",
                    "y_label": "Velocity (m/s)",
                    "show_legend": False,
                    "x_min": 0,
                    "x_max": 6,
                    "y_min": -6,
                    "y_max": 10,
                    "series": [
                        {
                            "label": "v(t)",
                            "points": [[0, -4], [2, -1], [4, 3], [6, 8]],
                        }
                    ],
                    "annotations": [
                        {"x": 0.9, "y": -4.6, "text": "negative velocity", "color": "#fda4af"},
                        {"x": 3.4, "y": 1.6, "text": "positive slope = positive acceleration", "color": "#86efac", "anchor": "start"},
                    ],
                },
            )
        ],
        "M1_L4": [
            vis(
                "m1_l4_constant_acceleration_graph",
                "Show one straight velocity-time forecast so constant acceleration appears as one steady gradient rather than as a slogan.",
                "Velocity-time graph: a straight line means one steady acceleration all the way through.",
                concept="constant_acceleration_forecast",
                title="Constant-Acceleration Forecast Board",
                template="physics_graph",
                meta={
                    "graph_type": "kinematics_time_series",
                    "title": "Constant-Acceleration Forecast Board",
                    "subtitle": "A straight velocity-time line keeps the same acceleration everywhere.",
                    "x_label": "Time (s)",
                    "y_label": "Velocity (m/s)",
                    "show_legend": False,
                    "x_min": 0,
                    "x_max": 4,
                    "y_min": 0,
                    "y_max": 16,
                    "series": [
                        {
                            "label": "Forecast",
                            "points": [[0, 2], [1, 5], [2, 8], [3, 11], [4, 14]],
                        }
                    ],
                    "annotations": [
                        {"x": 2.3, "y": 10.0, "text": "same slope all the way", "color": "#fde68a", "anchor": "start"},
                    ],
                },
            )
        ],
        "M1_L5": [
            vis(
                "m1_l5_distance_gradient_graph",
                "Show a distance-time example so the gradient meaning is fixed as speed before comparing it with another graph type.",
                "Distance-time example: slope means speed on these axes.",
                concept="graph_gradient_context",
                title="Gradient Meaning Comparator A",
                template="physics_graph",
                meta={
                    "graph_type": "generic_xy",
                    "title": "Gradient Meaning Comparator A",
                    "subtitle": "On a distance-time graph, slope means speed.",
                    "x_label": "Time (s)",
                    "y_label": "Distance (m)",
                    "show_legend": False,
                    "x_min": 0,
                    "x_max": 6,
                    "y_min": 0,
                    "y_max": 24,
                    "series": [
                        {
                            "label": "Distance-time",
                            "points": [[0, 0], [2, 8], [4, 16], [6, 24]],
                        }
                    ],
                    "annotations": [
                        {"x": 3.2, "y": 14.0, "text": "slope = 4 m/s", "color": "#86efac", "anchor": "start"},
                    ],
                },
            ),
            vis(
                "m1_l5_speed_gradient_graph",
                "Show a speed-time example with a matching-looking tilt so learners must use the axes to decide that the slope now means acceleration.",
                "Speed-time example: slope means acceleration on these axes.",
                concept="graph_gradient_context",
                title="Gradient Meaning Comparator B",
                template="physics_graph",
                meta={
                    "graph_type": "generic_xy",
                    "title": "Gradient Meaning Comparator B",
                    "subtitle": "On a speed-time graph, slope means acceleration.",
                    "x_label": "Time (s)",
                    "y_label": "Speed (m/s)",
                    "show_legend": False,
                    "x_min": 0,
                    "x_max": 6,
                    "y_min": 0,
                    "y_max": 14,
                    "series": [
                        {
                            "label": "Speed-time",
                            "points": [[0, 0], [2, 4], [4, 8], [6, 12]],
                        }
                    ],
                    "annotations": [
                        {"x": 3.2, "y": 8.0, "text": "slope = 2 m/s^2", "color": "#fbbf24", "anchor": "start"},
                    ],
                },
            ),
        ],
        "M1_L6": [
            vis(
                "m1_l6_area_distance_graph",
                "Show a speed-time graph with deliberate shaded area so the accumulated distance is tied to the whole region under the graph.",
                "Speed-time graph: shaded area gives total distance traveled.",
                concept="speed_time_area",
                title="Area-to-Distance Builder",
                template="physics_graph",
                meta={
                    "graph_type": "generic_xy",
                    "title": "Area-to-Distance Builder",
                    "subtitle": "On a speed-time graph, the shaded region builds total distance.",
                    "x_label": "Time (s)",
                    "y_label": "Speed (m/s)",
                    "show_legend": False,
                    "x_min": 0,
                    "x_max": 7,
                    "y_min": 0,
                    "y_max": 8,
                    "fill_under_series": True,
                    "fill_opacity": 0.24,
                    "series": [
                        {
                            "label": "Speed-time",
                            "points": [[0, 0], [1, 6], [4, 6], [6, 2], [7, 0]],
                        }
                    ],
                    "annotations": [
                        {"x": 3.1, "y": 3.0, "text": "area = distance", "color": "#fde68a"},
                    ],
                },
            )
        ],
    }
    lesson_analogies = {
        "M1_L1": (
            "Quest-Log is a two-layer telemetry system: the lane is the physical run, while the mission log is the time-stamped score sheet. "
            "Confusing the graph with the route is like mistaking a bank statement for the shopping trip that produced it."
        ),
        "M1_L2": (
            "A pace log is like a dashboard gauge with a trend trace: the gauge reading tells the speed now, but the tilt of the trace tells how fast the gauge itself is changing."
        ),
        "M1_L3": (
            "Think of velocity as a signed arrow on a control bar and acceleration as the instruction that rotates or stretches that arrow over time. "
            "The sign of the instruction belongs to the chosen positive direction, not to a vague feeling of speeding up."
        ),
        "M1_L4": (
            "The constant-acceleration board works like a flight computer calibrated for one steady thrust pattern. "
            "It is powerful precisely because the pattern is restricted; if the thrust pattern changes, the compact forecast stops being trustworthy."
        ),
        "M1_L5": (
            "Gradient is a rate-family idea, not a single named quantity. The same slanted geometry can mean dollars per item, metres per second, or metres per second squared depending on what the axes are comparing."
        ),
        "M1_L6": (
            "Area under a pace log is like stacking thin distance receipts from each time beat. Each strip is a tiny bit of distance, and the whole shaded region is the accumulated journey."
        ),
    }
    lesson_commitments = {
        "M1_L1": "Before reading the graph, decide which features tell the motion story and which features only tell the recorded totals.",
        "M1_L2": "Before answering, say aloud whether you are reading the graph height or the graph slope.",
        "M1_L3": "Before choosing the sign, mark the positive direction and compare the initial and final velocity arrows.",
        "M1_L4": "Before selecting an equation, list the knowns, name the unknown, and ask whether the acceleration is constant.",
        "M1_L5": "Before naming a gradient, name the axes so the rate family is fixed first.",
        "M1_L6": "Before using the shaded region, name the axes and decide why multiplying height by width gives distance here.",
    }

    for lesson_id, lesson in lessons.items():
        lesson["analogy_text"] = lesson_analogies[lesson_id]
        lesson["commitment_prompt"] = lesson_commitments[lesson_id]
        contract = lesson["contract"]
        contract["assessment_bank_targets"] = assessment_targets(7, 5, 10)
        contract["visual_assets"] = lesson_visual_assets[lesson_id]
        contract["animation_assets"] = [
            {
                "asset_id": f"{lesson_id.lower()}_animation",
                "concept": lesson_concepts[lesson_id],
                "phase_key": "analogical_grounding",
                "title": f"{lesson['title']} animation",
                "description": f"Animate the core representation change for {lesson['title']}.",
                "duration_sec": 8,
            }
        ]
        simulation_contract = dict(contract.get("simulation_contract") or {})
        simulation_contract.update(
            {
                "asset_id": f"{lesson_id.lower()}_simulation",
                "concept": lesson_concepts[lesson_id],
                "engine": "p5",
            }
        )
        contract["simulation_contract"] = simulation_contract

    lessons["M1_L1"]["diagnostic"].extend(
        [
            spec_mcq(
                "M1L1_D6",
                "Two straight distance-time segments are parallel but one starts higher. What must be the same?",
                ["the speed", "the starting point", "the total distance", "the pause time"],
                0,
                "Parallel straight segments on a distance-time graph have the same gradient.",
                ["graph_height_vs_gradient_confusion"],
            ),
            spec_short(
                "M1L1_D7",
                "A distance-time segment rises 18 m in 3 s. What pace does that segment show?",
                ["6", "6 m/s"],
                "Use pace = change in distance / change in time.",
                ["distance_time_story_confusion"],
            ),
        ]
    )
    lessons["M1_L1"]["capsule_checks"].extend(
        [
            spec_mcq(
                "M1L1_C4",
                "Why can a downward line not represent total distance traveled in this lesson?",
                ["Because total distance cannot decrease", "Because time stops", "Because negative distance is impossible in all graphs", "Because direction is missing"],
                0,
                "A total-distance record cannot shrink once distance has been accumulated.",
                ["graph_shape_path_confusion"],
            ),
            spec_short(
                "M1L1_C5",
                "Can the final point alone tell you whether there was a pause? Answer in a few words.",
                ["no", "not by itself", "no it cannot", "the final point alone is not enough"],
                "The final point gives the total by the end, not the full segment story.",
                ["distance_time_story_confusion", "graph_shape_path_confusion"],
            ),
        ]
    )
    lessons["M1_L1"]["transfer"].extend(
        [
            spec_short(
                "M1L1_T8",
                "In a few words, what does slope mean on a distance-time graph?",
                ["speed", "pace", "rate of distance change", "how quickly distance changes"],
                "Name the motion rate read from the graph, not the total distance.",
                ["graph_height_vs_gradient_confusion"],
            ),
            spec_mcq(
                "M1L1_T9",
                "Two mission logs both finish at 40 m after 10 s. One includes a 3 s pause. What must be true about its later moving section?",
                ["It must be steeper to catch up", "It must end lower", "It must have the same slope throughout", "It must represent reverse motion"],
                0,
                "A paused run that still finishes on time must gain distance faster later.",
                ["distance_time_story_confusion", "graph_height_vs_gradient_confusion"],
            ),
            spec_short(
                "M1L1_T10",
                "A graph rises from 12 m to 36 m between 4 s and 10 s. What speed does that segment show?",
                ["4", "4 m/s"],
                "Use the segment rise over the segment run.",
                ["distance_time_story_confusion"],
            ),
        ]
    )

    lessons["M1_L2"]["diagnostic"].extend(
        [
            spec_mcq(
                "M1L2_D6",
                "A flat speed-time line at 8 m/s means the object is...",
                ["moving at a constant 8 m/s", "stopped", "speeding up steadily", "reversing direction"],
                0,
                "Flat above zero means constant speed, not rest.",
                ["speed_time_story_confusion"],
            ),
            spec_short(
                "M1L2_D7",
                "Speed changes from 4 m/s to 10 m/s in 3 s. What acceleration does that show?",
                ["2", "2 m/s^2", "2 m/s/s"],
                "Use acceleration = change in speed / time.",
                ["acceleration_rate_confusion"],
            ),
        ]
    )
    lessons["M1_L2"]["capsule_checks"].extend(
        [
            spec_short(
                "M1L2_C4",
                "At a point where the graph height is 12 m/s and the slope is zero, what is happening?",
                ["constant speed of 12 m/s", "moving at 12 m/s with zero acceleration", "speed is 12 m/s and acceleration is zero"],
                "Read height as speed now and slope as acceleration.",
                ["graph_height_vs_gradient_confusion", "speed_time_story_confusion"],
            ),
            spec_mcq(
                "M1L2_C5",
                "Why can two speed-time graphs show the same speed at one instant but different accelerations?",
                ["Because equal height does not force equal slope", "Because speed and acceleration are the same", "Because time is missing", "Because acceleration depends only on distance"],
                0,
                "The graphs can meet at one height while tilting differently.",
                ["graph_height_vs_gradient_confusion", "acceleration_rate_confusion"],
            ),
        ]
    )
    lessons["M1_L2"]["transfer"].extend(
        [
            spec_short(
                "M1L2_T8",
                "In a few words, what does slope mean on a speed-time graph?",
                ["acceleration", "rate of speed change", "rate of velocity change"],
                "Name the change-rate quantity read from the slope.",
                ["graph_height_vs_gradient_confusion", "acceleration_rate_confusion"],
            ),
            spec_mcq(
                "M1L2_T9",
                "One speed-time line is high and flat. Another is lower but rises steeply. Which statement is correct?",
                ["The first has the greater speed now, but the second has the greater acceleration", "The second must always be faster", "Both have the same acceleration because both are above zero", "The first must be stopped because its slope is zero"],
                0,
                "Keep graph height and graph slope doing different jobs.",
                ["graph_height_vs_gradient_confusion", "acceleration_rate_confusion"],
            ),
            spec_short(
                "M1L2_T10",
                "Speed drops from 14 m/s to 6 m/s in 4 s. What acceleration does that show?",
                ["-2", "-2 m/s^2", "-2 m/s/s"],
                "Use the signed change in speed over time.",
                ["acceleration_rate_confusion"],
            ),
        ]
    )

    lessons["M1_L3"]["diagnostic"].extend(
        [
            spec_mcq(
                "M1L3_D6",
                "Velocity is -6 m/s and acceleration is +2 m/s^2. What is happening initially?",
                ["The object is moving in the negative direction and slowing down", "The object is moving in the negative direction and speeding up", "The object must be stationary", "The acceleration must also be negative"],
                0,
                "Positive acceleration can oppose a negative velocity and reduce the speed.",
                ["acceleration_sign_reasoning_confusion"],
            ),
            spec_short(
                "M1L3_D7",
                "Velocity changes from -6 m/s to +2 m/s in 4 s. What acceleration does that show?",
                ["2", "2 m/s^2", "2 m/s/s"],
                "Use the signed change in velocity divided by time.",
                ["acceleration_rate_confusion", "acceleration_sign_reasoning_confusion"],
            ),
        ]
    )
    lessons["M1_L3"]["capsule_checks"].extend(
        [
            spec_short(
                "M1L3_C4",
                "Can positive acceleration happen while the object is moving in the negative direction? Answer briefly.",
                ["yes", "yes if the velocity is negative and becoming less negative", "yes if the positive acceleration opposes the negative velocity", "yes it can"],
                "Acceleration sign and velocity sign do not have to match.",
                ["acceleration_sign_reasoning_confusion"],
            ),
            spec_mcq(
                "M1L3_C5",
                "Zero acceleration with velocity -3 m/s means that the object is...",
                ["moving at a constant -3 m/s", "stopped", "speeding up negatively", "changing direction every second"],
                0,
                "Zero acceleration means the velocity is staying fixed.",
                ["acceleration_rate_confusion"],
            ),
        ]
    )
    lessons["M1_L3"]["transfer"].extend(
        [
            spec_short(
                "M1L3_T8",
                "In a few words, what does the sign of acceleration tell you?",
                ["direction of the velocity change", "direction of acceleration relative to the chosen positive direction", "which direction the velocity is changing"],
                "The sign belongs to the chosen direction convention.",
                ["acceleration_sign_reasoning_confusion"],
            ),
            spec_mcq(
                "M1L3_T9",
                "Velocity is +12 m/s and acceleration is -3 m/s^2 for 2 s. Which statement is correct?",
                ["The object is still moving in the positive direction but more slowly", "The object must already be moving in the negative direction", "The acceleration is zero because the speed stays positive", "The speed must increase because the velocity is positive"],
                0,
                "A negative acceleration can reduce a positive velocity without reversing it immediately.",
                ["acceleration_sign_reasoning_confusion"],
            ),
            spec_short(
                "M1L3_T10",
                "Velocity changes from 8 m/s to 0 m/s in 2 s. What acceleration does that show?",
                ["-4", "-4 m/s^2", "-4 m/s/s"],
                "Use the signed velocity change over the time interval.",
                ["acceleration_rate_confusion"],
            ),
        ]
    )

    lessons["M1_L4"]["diagnostic"].extend(
        [
            spec_mcq(
                "M1L4_D6",
                "Which condition must be checked before using a suvat equation in this lesson?",
                ["The acceleration is constant", "The speed is zero", "The graph is curved", "The distance is negative"],
                0,
                "These equations summarize one steady acceleration pattern.",
                ["constant_acceleration_condition_confusion"],
            ),
            spec_short(
                "M1L4_D7",
                "If u = 5 m/s, a = 2 m/s^2, and t = 4 s, what is v?",
                ["13", "13 m/s"],
                "Use v = u + at for the direct final-speed forecast.",
                ["suvat_selection_confusion", "motion_formula_story_confusion"],
            ),
        ]
    )
    lessons["M1_L4"]["capsule_checks"].extend(
        [
            spec_short(
                "M1L4_C4",
                "In a few words, what does the 1/2at^2 part represent?",
                ["extra distance from acceleration", "the triangle distance from acceleration", "distance added by the steady acceleration", "additional distance beyond ut"],
                "Think about the extra triangular area added above the starting-speed rectangle.",
                ["motion_formula_story_confusion"],
            ),
            spec_mcq(
                "M1L4_C5",
                "Why does s = (u + v) / 2 x t work only for constant acceleration here?",
                ["Because the average velocity sits halfway between u and v only for uniform change", "Because distance never depends on time", "Because u and v must be zero", "Because the equation ignores acceleration completely"],
                0,
                "The midpoint average depends on the change being uniform.",
                ["constant_acceleration_condition_confusion", "motion_formula_story_confusion"],
            ),
        ]
    )
    lessons["M1_L4"]["transfer"].extend(
        [
            spec_short(
                "M1L4_T8",
                "Why should you not trust suvat directly when acceleration changes during the motion?",
                ["because suvat assumes constant acceleration", "because the equations only model constant acceleration", "because the acceleration is not constant", "because the steady-change condition is broken"],
                "Name the condition the equations require.",
                ["constant_acceleration_condition_confusion"],
            ),
            spec_mcq(
                "M1L4_T9",
                "You know u, a, and t and want v. Which equation is the direct choice?",
                ["v = u + at", "s = ut + 1/2at^2", "v^2 = u^2 + 2as", "s = (u + v) / 2 x t"],
                0,
                "Choose the relation that reaches the unknown without introducing extra variables.",
                ["suvat_selection_confusion"],
            ),
            spec_short(
                "M1L4_T10",
                "If u = 4 m/s, a = 3 m/s^2, and t = 2 s, what distance does s = ut + 1/2at^2 give?",
                ["14", "14 m"],
                "Combine the starting-speed rectangle with the acceleration triangle.",
                ["motion_formula_story_confusion"],
            ),
        ]
    )

    lessons["M1_L5"]["diagnostic"].extend(
        [
            spec_mcq(
                "M1L5_D6",
                "On a distance-time graph, zero slope means that the object is...",
                ["stopped", "speeding up steadily", "moving backward", "at the highest speed"],
                0,
                "Zero slope means no new distance is being added.",
                ["graph_gradient_context_confusion"],
            ),
            spec_short(
                "M1L5_D7",
                "A distance-time line rises 24 m in 6 s. What speed does that slope show?",
                ["4", "4 m/s"],
                "Use distance change divided by time change.",
                ["graph_gradient_context_confusion"],
            ),
        ]
    )
    lessons["M1_L5"]["capsule_checks"].extend(
        [
            spec_short(
                "M1L5_C4",
                "On a speed-time graph, what does zero slope mean?",
                ["zero acceleration", "constant speed", "constant velocity", "no change in speed"],
                "The height may stay above zero even when the slope is zero.",
                ["graph_gradient_context_confusion"],
            ),
            spec_mcq(
                "M1L5_C5",
                "Why can the same-looking tilt mean different things on two motion graphs?",
                ["Because the axes are different", "Because slope never has units", "Because graphs ignore time", "Because one graph must be wrong"],
                0,
                "The axes decide the rate family represented by the tilt.",
                ["graph_gradient_context_confusion", "multi_representation_motion_confusion"],
            ),
        ]
    )
    lessons["M1_L5"]["transfer"].extend(
        [
            spec_short(
                "M1L5_T8",
                "Why must you name the axes before naming the slope?",
                ["because the axes decide the meaning of the slope", "because the graph type decides whether slope means speed or acceleration", "because slope meaning comes from the axes", "because the same tilt can mean different rates on different graphs"],
                "State why the graph context fixes the meaning first.",
                ["graph_gradient_context_confusion", "multi_representation_motion_confusion"],
            ),
            spec_mcq(
                "M1L5_T9",
                "Which pair is matched correctly?",
                ["distance-time slope -> speed; speed-time slope -> acceleration", "distance-time slope -> acceleration; speed-time slope -> speed", "distance-time slope -> distance; speed-time slope -> speed", "distance-time slope -> time; speed-time slope -> distance"],
                0,
                "Match each slope meaning to the graph axes.",
                ["graph_gradient_context_confusion"],
            ),
            spec_short(
                "M1L5_T10",
                "A speed-time line rises from 2 m/s to 10 m/s in 4 s. What acceleration does the slope show?",
                ["2", "2 m/s^2", "2 m/s/s"],
                "Use change in speed divided by change in time.",
                ["graph_gradient_context_confusion"],
            ),
        ]
    )

    lessons["M1_L6"]["diagnostic"].extend(
        [
            spec_mcq(
                "M1L6_D6",
                "What does the area under a speed-time graph represent in this module?",
                ["total distance traveled", "acceleration", "final speed only", "time alone"],
                0,
                "On a speed-time graph, area accumulates distance.",
                ["area_under_graph_confusion"],
            ),
            spec_short(
                "M1L6_D7",
                "An object moves at 5 m/s for 4 s. What distance does the rectangle area give?",
                ["20", "20 m"],
                "Use distance = speed x time for the rectangular area.",
                ["area_under_graph_confusion"],
            ),
        ]
    )
    lessons["M1_L6"]["capsule_checks"].extend(
        [
            spec_short(
                "M1L6_C4",
                "Why does the area rule work on a speed-time graph?",
                [
                    "because speed multiplied by time gives distance",
                    "because the axes are speed and time so area gives distance",
                    "because each strip is speed x time",
                    "because the area accumulates distance from speed and time",
                    "because the x axis is time and the y axis is speed so the area has units of distance",
                    "because m/s times s gives m",
                    "because each strip is speed times time and the strips add to total distance",
                ],
                "Use the axes to justify the physical meaning of the area.",
                ["area_under_graph_confusion", "multi_representation_motion_confusion"],
            ),
            spec_mcq(
                "M1L6_C5",
                "Two different speed-time graphs enclose the same total area over the same interval. What must be the same?",
                ["the total distance", "the final speed", "the acceleration at every point", "the graph shape"],
                0,
                "Equal total area means equal accumulated distance.",
                ["area_under_graph_confusion"],
            ),
        ]
    )
    lessons["M1_L6"]["transfer"].extend(
        [
            spec_short(
                "M1L6_T8",
                "In a few words, what does the area under a speed-time graph represent?",
                ["total distance", "distance traveled", "accumulated distance", "distance covered"],
                "Name the accumulated quantity, not the graph shape.",
                ["area_under_graph_confusion"],
            ),
            spec_mcq(
                "M1L6_T9",
                "One speed-time graph is a tall narrow triangle and another is a lower wider trapezium. If their areas match, then...",
                ["they represent the same total distance", "they must have the same final speed", "they must have the same acceleration", "they must be the same graph"],
                0,
                "Area, not shape alone, controls the total distance.",
                ["area_under_graph_confusion", "multi_representation_motion_confusion"],
            ),
            spec_short(
                "M1L6_T10",
                "Speed increases steadily from 2 m/s to 10 m/s over 4 s. What distance is traveled?",
                ["24", "24 m"],
                "Use average speed x time or rectangle + triangle area.",
                ["area_under_graph_confusion"],
            ),
        ]
    )


apply_m1_enhancements()


RELEASE_CHECKS = [
    "Every mastery-tested relationship is explicitly taught before mastery.",
    "Every graph feature is named with its physical meaning before students are assessed on it.",
    "At least one non-text representation is used and checked.",
    "Visuals are readable on desktop and mobile.",
]


M1_MODULE_DOC, _LESSONS, _SIMS = build_nextgen_module_scaffold(
    M1_MODULE_ID,
    "Kinematics, Graphs & Constant Acceleration",
    M1_SPEC["module_description"],
    [lesson["title"] for lesson in M1_SPEC["lessons"]],
    M1_ALLOWLIST,
    sequence=5,
    level="Module 1",
    estimated_minutes=210,
)
M1_MODULE_DOC.update({
    "content_version": M1_CONTENT_VERSION,
    "mastery_outcomes": list(M1_SPEC["mastery_outcomes"]),
    "misconception_tag_allowlist": M1_ALLOWLIST,
    "authoring_standard": "lesson_authoring_spec_v1",
    "updated_utc": utc_now(),
})
LESSON_BY_ID = {str(lesson["lesson_id"]): lesson for lesson in _LESSONS}
SIM_BY_LESSON = {str(lesson["lesson_id"]): sim for lesson, sim in zip(_LESSONS, _SIMS)}


def build_question(spec: Dict[str, Any]) -> Dict[str, Any]:
    if str(spec.get("kind") or "") == "mcq":
        question = make_mcq(str(spec["id"]), str(spec["prompt"]), list(spec["choices"]), int(spec["answer_index"]), str(spec["hint"]), list(spec["tags"]))
    else:
        question = make_short(str(spec["id"]), str(spec["prompt"]), list(spec["accepted_answers"]), str(spec["hint"]), list(spec["tags"]))
    if spec.get("acceptance_rules"):
        question["acceptance_rules"] = dict(spec["acceptance_rules"])
    if spec.get("skill_tags"):
        question["skill_tags"] = [str(tag) for tag in spec["skill_tags"]]
    return question


def build_prompt_blocks(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [prompt_block(str(item["prompt"]), str(item["hint"])) for item in items]


def build_formulas(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [formula(str(item["equation"]), str(item["meaning"]), list(item["units"]), str(item["conditions"])) for item in items]


def build_representations(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [rep(str(item["kind"]), str(item["purpose"])) for item in items]


def build_examples(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        example(
            str(item["prompt"]),
            list(item["steps"]),
            str(item["final_answer"]),
            str(item["why_it_matters"]),
            str(item.get("answer_reason") or ""),
        )
        for item in items
    ]


def build_visuals(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        vis(
            str(item["asset_id"]),
            str(item.get("purpose") or item.get("caption") or item.get("title") or item["asset_id"]),
            str(item.get("caption") or item.get("purpose") or item.get("title") or item["asset_id"]),
            concept=str(item.get("concept") or ""),
            title=str(item.get("title") or ""),
            phase_key=str(item.get("phase_key") or "analogical_grounding"),
            template=str(item.get("template") or "auto"),
            meta=dict(item.get("meta") or {}),
            width=int(item.get("width") or 1280),
            height=int(item.get("height") or 720),
        )
        for item in items
    ]


def build_animations(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        anim(
            str(item["asset_id"]),
            str(item.get("concept") or item["asset_id"]),
            str(item.get("title") or item["asset_id"]),
            str(item.get("description") or item.get("title") or item["asset_id"]),
            phase_key=str(item.get("phase_key") or "analogical_grounding"),
            duration_sec=int(item.get("duration_sec") or 8),
        )
        for item in items
    ]


def configure_sim(spec: Dict[str, Any]) -> None:
    lesson = LESSON_BY_ID[str(spec["id"])]
    sim = SIM_BY_LESSON[str(spec["id"])]
    sim_spec = spec["sim"]
    lesson["phases"]["simulation_inquiry"]["lab_id"] = str(sim_spec["lab_id"])
    sim.update({
        "lab_id": str(sim_spec["lab_id"]),
        "module_id": M1_MODULE_ID,
        "title": str(sim_spec["title"]),
        "description": str(sim_spec["description"]),
        "instructions": list(sim_spec["instructions"]),
        "expected_outcomes": list(sim_spec["outcomes"]),
        "telemetry_schema_hint": {"fields": list(sim_spec["fields"]), "sim_depth_meaning": str(sim_spec["depth"])} ,
        "updated_utc": utc_now(),
    })


def configure_lesson(spec: Dict[str, Any]) -> None:
    lesson = LESSON_BY_ID[str(spec["id"])]
    lesson["updated_utc"] = utc_now()
    lesson["phases"]["diagnostic"] = {
        "two_tier": True,
        "items": [build_question(item) for item in spec["diagnostic"]],
        "notes": "Use the opening check to surface the main graph or motion misconception before the lesson deepens it.",
    }
    lesson["phases"]["analogical_grounding"] = {
        "analogy_text": str(spec["analogy_text"]),
        "commitment_prompt": str(spec["commitment_prompt"]),
        "micro_prompts": build_prompt_blocks(list(spec["micro_prompts"])),
    }
    lesson["phases"]["simulation_inquiry"]["inquiry_prompts"] = build_prompt_blocks(list(spec["inquiry"]))
    lesson["phases"]["concept_reconstruction"] = {
        "prompts": list(spec["recon_prompts"]),
        "capsules": [{
            "prompt": str(spec["capsule_prompt"]),
            "checks": [build_question(item) for item in spec["capsule_checks"]],
        }],
    }
    lesson["phases"]["transfer"] = {
        "items": [build_question(item) for item in spec["transfer"]],
        "notes": "Use transfer to check whether the idea survives a fresh representation, story, or graph context.",
    }
    contract = dict(spec["contract"])
    contract["misconception_focus"] = safe_tags(list(contract["misconception_focus"]))
    contract["formulas"] = build_formulas(list(contract["formulas"]))
    contract["representations"] = build_representations(list(contract["representations"]))
    contract["worked_examples"] = build_examples(list(contract["worked_examples"]))
    contract["visual_assets"] = build_visuals(list(contract["visual_assets"]))
    contract["animation_assets"] = build_animations(list(contract.get("animation_assets") or []))
    contract["simulation_contract"] = dict(contract.get("simulation_contract") or {})
    contract["assessment_bank_targets"] = dict(contract.get("assessment_bank_targets") or {})
    contract["release_checks"] = list(RELEASE_CHECKS)
    lesson["authoring_contract"] = contract


for lesson_spec in M1_SPEC["lessons"]:
    configure_sim(lesson_spec)
    configure_lesson(lesson_spec)


M1_LESSONS: List[Tuple[str, Dict[str, Any]]] = [(str(lesson["lesson_id"]), lesson) for lesson in _LESSONS]
M1_SIM_LABS: List[Tuple[str, Dict[str, Any]]] = [(str(sim["lab_id"]), sim) for sim in _SIMS]

validate_nextgen_module(M1_MODULE_DOC, [payload for _, payload in M1_LESSONS], [payload for _, payload in M1_SIM_LABS], M1_ALLOWLIST)
plan_module_assets(M1_LESSONS, M1_SIM_LABS, public_base="/lesson_assets")


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module M1 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()

    project = get_project_id(args.project)
    apply = bool(args.apply)
    db = init_firebase(project) if apply else None

    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M1_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M1_SIM_LABS]
    asset_root = args.asset_root or str(default_asset_root())
    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    plan: List[Tuple[str, str]] = [("modules", M1_MODULE_ID)] + [("lessons", doc_id) for doc_id, _ in lesson_pairs] + [("sim_labs", doc_id) for doc_id, _ in sim_pairs]
    print(f"Project: {project}")
    print(f"Mode: {'APPLY (writes enabled)' if apply else 'DRY RUN (no writes)'}")
    if args.compile_assets:
        print(f"Asset root: {asset_root}")
        print(f"Public base: {args.public_base}")
    print_preview("Planned upserts", plan)

    upsert_doc(db, "modules", M1_MODULE_ID, M1_MODULE_DOC, apply)
    for doc_id, payload in lesson_pairs:
        upsert_doc(db, "lessons", doc_id, payload, apply)
    for doc_id, payload in sim_pairs:
        upsert_doc(db, "sim_labs", doc_id, payload, apply)

    print("DONE")


if __name__ == "__main__":
    main()
