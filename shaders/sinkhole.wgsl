struct Params {
  time: f32,
  resolution: vec2f,
}

@group(0) @binding(0) var<uniform> params: Params;

@fragment
fn fs_main(@location(0) uv: vec2f) -> @location(0) vec4f {
  let center = vec2f(0.5, 0.5);
  let dist = distance(uv, center);
  let pulse = sin(params.time * 2.0 - dist * 10.0) * 0.5 + 0.5;
  let color = vec3f(0.83, 1.0, 0.0) * pulse; // Acid Lime #D4FF00
  return vec4f(color, 1.0);
}
