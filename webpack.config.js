var webpack = require('webpack');

module.exports = {
    entry: './src/streamliner.js',
    output: {
        path: './public',
        filename: 'streamliner.js'
    },
    resolve: {
        extensions: ['', '.js', '.json'],
        modulesDirectories: [
            'node_modules',
            'bower_components'
        ],
        alias: {openpgp: 'openpgp',
                cheerio: 'cheerio'
        },
        loaders:
            { test: /\.json$/, loader: "json" }       
    }
};