const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');

module.exports = {
  entry: {
    background: './src/background/service-worker.ts',
    content: './src/content/content-script.ts',
    popup: './src/popup/popup.ts',
    blocked: './src/pages/blocked.ts'
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: 'ts-loader',
        exclude: /node_modules/
      },
      {
        test: /\.css$/,
        use: ['style-loader', 'css-loader']
      }
    ]
  },
  resolve: {
    extensions: ['.ts', '.js']
  },
  output: {
    filename: '[name].js',
    path: path.resolve(__dirname, 'dist'),
    clean: true
  },
  plugins: [
    new CopyPlugin({
      patterns: [
        { from: 'src/manifest.json', to: 'manifest.json' },
        { from: 'src/popup/popup.html', to: 'popup.html' },
        { from: 'src/popup/popup.css', to: 'popup.css' },
        { from: 'src/pages/blocked.html', to: 'blocked.html' },
        { from: 'src/pages/blocked.css', to: 'blocked.css' },
        { from: 'src/assets', to: 'assets', noErrorOnMissing: true },
        { from: 'src/rules', to: 'rules', noErrorOnMissing: true }
      ]
    })
  ]
};
