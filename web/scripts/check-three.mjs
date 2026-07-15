import { execFileSync } from 'node:child_process'
import { realpathSync } from 'node:fs'

const output = execFileSync('npm', ['ls', 'three', '--parseable', '--all'], { encoding: 'utf8' })
const installations = [...new Set(
  output
    .split(/\r?\n/)
    .filter((line) => line.includes('node_modules/three'))
    .map((line) => realpathSync(line)),
)]

if (installations.length !== 1) {
  throw new Error(`Expected one Three.js installation, found ${installations.length}: ${installations.join(', ')}`)
}

console.log(`Three.js resolved once: ${installations[0]}`)
