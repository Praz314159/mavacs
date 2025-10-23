#!/bin/bash

# scripts/profile.sh - Auto-detecting profiling script for MAVACS

set -e

# Create directories if they don't exist
mkdir -p profiles/vac
mkdir -p profiles/cms
mkdir -p docs

# Detect which workflow is active
WORKFLOW=$(grep -A 1 "// Swap between workflows" src/main.rs | grep "run_" | grep -v "//" | sed 's/.*run_\(.*\)_workflow.*/\1/')

if [ -z "$WORKFLOW" ]; then
    echo "❌ Could not detect active workflow in main.rs"
    echo "Make sure one of the run_*_workflow() calls is uncommented"
    exit 1
fi

echo "📍 Detected workflow: $WORKFLOW"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Run heap profiler
echo ""
echo "🔬 Running heap profiler..."
cargo run --release --features dhat-heap
mv dhat-heap.json profiles/${WORKFLOW}/heap_${TIMESTAMP}.json
echo "✅ Saved to profiles/${WORKFLOW}/heap_${TIMESTAMP}.json"

# Run CPU profiler
echo ""
echo "🔥 Running CPU profiler..."
sudo cargo flamegraph --release -o profiles/${WORKFLOW}/flame_${TIMESTAMP}.svg
echo "✅ Saved to profiles/${WORKFLOW}/flame_${TIMESTAMP}.svg"

# Create/update performance doc
PERF_DOC="docs/performance_${WORKFLOW}.md"

# Initialize doc if it doesn't exist
if [ ! -f "$PERF_DOC" ]; then
    cat > "$PERF_DOC" << EOF
# Performance Tracking - ${WORKFLOW^^} Workflow

This document tracks performance profiles for the ${WORKFLOW} workflow.

---

EOF
fi

# Add entry template
cat >> "$PERF_DOC" << EOF
## Run: $TIMESTAMP

**Profile files:**
- Heap: \`profiles/${WORKFLOW}/heap_${TIMESTAMP}.json\`
- CPU: \`profiles/${WORKFLOW}/flame_${TIMESTAMP}.svg\`

**TODO: Fill in observations**
- Peak memory:
- Top heap allocators:
  1.
  2.
  3.
- CPU hotspots:
  1.
  2.
  3.
- Notes:

---

EOF

echo ""
echo "📊 View results:"
echo "   Heap: https://nnethercote.github.io/dh_view/dh_view.html"
echo "         (upload profiles/${WORKFLOW}/heap_${TIMESTAMP}.json)"
echo "   CPU:  open profiles/${WORKFLOW}/flame_${TIMESTAMP}.svg"
echo ""
echo "📝 Document findings in: $PERF_DOC"
echo ""
echo "📈 Profile history for ${WORKFLOW}:"
ls -lht profiles/${WORKFLOW}/ | head -10
