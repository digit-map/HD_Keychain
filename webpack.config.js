const path = require('path')

module.exports = {
  target: 'web',
  mode: 'production',
  entry: {
    index: './src/index.ts',
  },
  module: {
    rules: [{
      test: /\.ts$/,
      use: {
        loader: 'ts-loader',
        options: {
          configFile: 'tsconfig.prod.json'
        }
      },
      exclude: /node_modules/,
    }, ],
  },
  resolve: {
    extensions: ['.ts', '.js'],
  },
  output: {
    filename: '[name].js',
    path: path.resolve(__dirname, 'lib', 'umd'),
    libraryTarget: 'umd',
    library: 'HDKeychain',
    globalObject: 'globalThis',
  },
}
