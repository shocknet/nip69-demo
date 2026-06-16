const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');
const glob = require('glob');

module.exports = (env, argv) => {
    const isProduction = argv.mode === 'production';

    // Find all HTML files in src
    const htmlFiles = glob.sync('./src/*.html');
    const htmlPlugins = htmlFiles.map(file => {
        const name = path.basename(file, '.html');
        let chunks = [];
        if (name === 'index') chunks = ['main', 'utils'];
        else if (name === 'debit') chunks = ['debit', 'utils'];
        else if (name === 'offers') chunks = ['main', 'static'];
        else chunks = ['static'];
        return new HtmlWebpackPlugin({
            template: file,
            filename: path.basename(file),
            chunks,
        });
    });

    return {
        entry: {
            utils: './src/utils.ts',
            main: './src/index.ts',
            debit: './src/debit.ts',
            static: './src/static.ts',
            manage: './src/manage.ts',
        },
        output: {
            filename: '[name].js',
            path: path.resolve(__dirname, 'dist'),
            clean: {
                keep: /(favicon\.png|clinkmedev-og-card\.png|CLINK_(dark|light)\.svg)$/,
            },
        },
        resolve: {
            extensions: ['.ts', '.js']
        },
        module: {
            rules: [
                {
                    test: /\.ts$/,
                    use: 'ts-loader',
                    exclude: /node_modules/
                },
                {
                    test: /\.css$/i,
                    use: [
                        isProduction ? MiniCssExtractPlugin.loader : 'style-loader',
                        'css-loader'
                    ],
                },
                {
                    test: /\.png$/,
                    type: 'asset/resource',
                    generator: {
                        filename: '[name][ext]'
                    }
                }
            ]
        },
        plugins: [
            ...htmlPlugins,
            ...(isProduction ? [new MiniCssExtractPlugin()] : [])
        ],
        devServer: {
            static: {
                directory: path.join(__dirname, 'dist'),
            },
            compress: true,
            port: 8787,
            open: true,
        },
        mode: isProduction ? 'production' : 'development',
    };
};