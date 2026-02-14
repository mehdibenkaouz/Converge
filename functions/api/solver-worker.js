// solver-worker.js
// WebWorker: contiene SOLO logica pura (niente DOM).

function key(x, y){ return x + "," + y; }

function neighbors4(x, y, N){
  const out = [];
  if (x > 0) out.push([x-1, y]);
  if (x < N-1) out.push([x+1, y]);
  if (y > 0) out.push([x, y-1]);
  if (y < N-1) out.push([x, y+1]);
  return out;
}

function computeBreaksForSnapshot(snap){
  const tiles = Object.values(snap.tilesById);
  if (!tiles.length) return {breakColorIds:[], idsToRemove:[]};
  const byColor = new Map();
  for (const t of tiles){
    if (!byColor.has(t.colorId)) byColor.set(t.colorId, []);
    byColor.get(t.colorId).push(t);
  }
  const idsToRemove = [];
  const breakColorIds = [];
  for (const [colorId, list] of byColor.entries()){
    if (list.length < 2) continue;
    const target = new Set(list.map(t => key(t.x,t.y)));
    const visited = new Set();
    const q = [list[0]];
    visited.add(key(list[0].x, list[0].y));
    while (q.length){
      const cur = q.shift();
      for (const [nx,ny] of neighbors4(cur.x, cur.y, snap.N)){
        const k = key(nx,ny);
        if (visited.has(k)) continue;
        const id = snap.board[ny][nx];
        if (id == null) continue;
        const t = snap.tilesById[id];
        if (!t || t.colorId !== colorId) continue;
        visited.add(k);
        q.push(t);
      }
    }
    let allConnected = true;
    for (const pos of target){
      if (!visited.has(pos)) {allConnected=false; break;}
    }
    if (allConnected){
      breakColorIds.push(colorId);
      for (const t of list) idsToRemove.push(t.id);
    }
  }
  return {breakColorIds, idsToRemove};
}

function simulateMoveFromSnapshot(snap, dir){
  const N = snap.N;

  let movedAny = false;
  const boardNew = Array.from({length:N}, () => Array.from({length:N}, () => null));
  const tilesById = snap.tilesById;

  const updateTile = (id, nx, ny) => {
    const t = tilesById[id];
    if (t.x !== nx || t.y !== ny) movedAny = true;
    t.x = nx; t.y = ny;
    boardNew[ny][nx] = Number(id);
  };

  if (dir === "left" || dir === "right"){
    for (let y=0; y<N; y++){
      const line = [];
      for (let x=0; x<N; x++){
        const id = snap.board[y][x];
        if (id != null) line.push(id);
      }
      if (dir === "right") line.reverse();
      for (let i=0; i<line.length; i++){
        const id = line[i];
        const x = (dir === "left") ? i : (N-1-i);
        updateTile(id, x, y);
      }
    }
  } else {
    for (let x=0; x<N; x++){
      const line = [];
      for (let y=0; y<N; y++){
        const id = snap.board[y][x];
        if (id != null) line.push(id);
      }
      if (dir === "down") line.reverse();
      for (let i=0; i<line.length; i++){
        const id = line[i];
        const y = (dir === "up") ? i : (N-1-i);
        updateTile(id, x, y);
      }
    }
  }

  snap.board = boardNew;

  const {breakColorIds, idsToRemove} = computeBreaksForSnapshot(snap);
  const removedIds = [];

  if (idsToRemove.length){
    const idSet = new Set(idsToRemove.map(Number));
    for (const id of idSet){
      const t = snap.tilesById[id];
      if (!t) continue;
      snap.board[t.y][t.x] = null;
      delete snap.tilesById[id];
      removedIds.push(id);
    }
  }

  return {
    moved: movedAny,
    brokenCount: removedIds.length,
    breakColorIds,
    removedIds,
    snapshot: snap,
  };
}

function signatureForSnapshot(snap){
  let out = snap.N + "|";
  for (let y=0; y<snap.N; y++){
    for (let x=0; x<snap.N; x++){
      const id = snap.board[y][x];
      if (id == null) out += ".";
      else out += String(snap.tilesById[id].colorId);
      out += ",";
    }
    out += ";";
  }
  return out;
}

function cloneSnapshot(s){
  const tilesById = {};
  for (const idStr in s.tilesById){
    const t = s.tilesById[idStr];
    tilesById[idStr] = {id: t.id, colorId: t.colorId, x: t.x, y: t.y};
  }
  return {
    N: s.N,
    board: s.board.map(r => r.slice()),
    tilesById
  };
}

// versione “budget mosse”
function analyzeSolvabilityForSnapshotWithMoves(
  rootSnap,
  initialMoves,
  { timeBudgetMs = 140, nodeLimit = 180000 } = {}
){
  const t0 = performance.now();
  const dirs = ["up","down","left","right"];

  const startMoves = Math.max(0, (initialMoves|0));
  const root = cloneSnapshot(rootSnap);

  const totalTiles0 = Object.keys(root.tilesById).length;
  const movesCap = startMoves + Math.floor(totalTiles0 / 2);
  const capMoves = (m) => Math.min(movesCap, Math.max(0, m|0));

  const heap = [];
  const heapPush = (node) => {
    heap.push(node);
    let i = heap.length - 1;
    while (i > 0){
      const p = ((i - 1) >> 1);
      if (heap[p].prio >= heap[i].prio) break;
      const tmp = heap[p]; heap[p] = heap[i]; heap[i] = tmp;
      i = p;
    }
  };
  const heapPop = () => {
    if (!heap.length) return null;
    const top = heap[0];
    const last = heap.pop();
    if (heap.length){
      heap[0] = last;
      let i = 0;
      for (;;){
        const l = i*2+1, r = l+1;
        let best = i;
        if (l < heap.length && heap[l].prio > heap[best].prio) best = l;
        if (r < heap.length && heap[r].prio > heap[best].prio) best = r;
        if (best === i) break;
        const tmp = heap[i]; heap[i] = heap[best]; heap[best] = tmp;
        i = best;
      }
    }
    return top;
  };

  const visited = new Map(); // signature -> bestMovesSeen
  const sig0 = signatureForSnapshot(root);
  visited.set(sig0, startMoves);

  const startTiles = Object.keys(root.tilesById).length;
  heapPush({
    snap: root,
    moves: startMoves,
    firstDir: null,
    prio: startTiles * 1000 + startMoves
  });

  let expanded = 0;

  while (heap.length){
    if (expanded >= nodeLimit) return {status:"unknown", firstDir:null, expanded, visited: visited.size};
    if ((performance.now() - t0) > timeBudgetMs) return {status:"unknown", firstDir:null, expanded, visited: visited.size};

    const cur = heapPop();
    if (!cur) break;
    expanded++;

    const tilesLeft = Object.keys(cur.snap.tilesById).length;
    if (tilesLeft === 0){
      return {status:"solved", firstDir: cur.firstDir, expanded, visited: visited.size};
    }
    if (cur.moves <= 0) continue;

    for (const dir of dirs){
      const nextSnap = cloneSnapshot(cur.snap);
      const res = simulateMoveFromSnapshot(nextSnap, dir);

      if (!res.moved && res.brokenCount === 0) continue;

      const nextMoves = capMoves(cur.moves - 1);
      const sig = signatureForSnapshot(res.snapshot);

      const prevBest = visited.get(sig);
      if (prevBest != null && prevBest >= nextMoves) continue;
      visited.set(sig, nextMoves);

      const nextTiles = Object.keys(res.snapshot.tilesById).length;
      const prio = nextTiles * 1000 + nextMoves;

      heapPush({
        snap: res.snapshot,
        moves: nextMoves,
        firstDir: cur.firstDir || dir,
        prio
      });
    }
  }

  return {status:"exhausted", firstDir:null, expanded, visited: visited.size};
}

self.onmessage = (e) => {
  const { id, snap, movesBudget, opts } = e.data || {};
  try{
    const res = analyzeSolvabilityForSnapshotWithMoves(snap, movesBudget, opts || {});
    self.postMessage({ id, ok:true, res });
  }catch(err){
    self.postMessage({ id, ok:false, err: String(err && err.message ? err.message : err) });
  }
};