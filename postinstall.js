if (process.env.npm_config_build_from_source) {
	console.log('building @matrix-org/matrix-sdk-crypto-nodejs from source');
	require('child_process').spawnSync(process.env.npm_execpath || 'npm', ['run', 'release-build']);
} else {
	require('./download-lib.js');
}
