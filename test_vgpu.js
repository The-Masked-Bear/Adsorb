import { init, effect, target } from 'vgpu/node';

async function main() {
  console.log('Initializing VGPU Node context...');
  const gpu = await init();
  const width = 64;
  const height = 64;
  const colorTarget = target(gpu, { size: [width, height] });

  const SHADER = `
    @fragment fn main() -> @location(0) vec4f {
      return vec4f(0.83, 1.0, 0.0, 1.0); // Acid Lime #D4FF00
    }
  `;

  console.log('Rendering offscreen WebGPU target (64x64)...');
  effect(gpu, SHADER).draw(colorTarget);

  const pixels = await colorTarget.read();
  console.log(`Successfully read ${pixels.length} bytes from WebGPU target!`);
  console.log(`Sample pixel (RGBA): [${pixels[0]}, ${pixels[1]}, ${pixels[2]}, ${pixels[3]}]`);

  gpu.dispose();
  console.log('VGPU test passed successfully!');
}

main().catch(err => {
  console.error('VGPU test failed:', err);
  process.exit(1);
});
