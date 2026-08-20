const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');

const chunksFor = (name) => {
    switch (name) {
        case 'offers':
            return ['offers'];
        case 'debit':
            return ['debit'];
        default:
            return ['static'];
    }
};

const htmlPages = [
    'index',
    'offers',
    'debit',
    'apps',
    'specs',
    'contact',
];

module.exports = (env, argv) => {
    const isProduction = argv.mode === 'production';
    const htmlPlugins = htmlPages.map(name => new HtmlWebpackPlugin({
        template: `./src/${name}.html`,
        filename: `${name}.html`,
        chunks: chunksFor(name),
    }));

    return {
        entry: {
            offers: './src/offers.ts',
            debit: './src/debit.ts',
            static: './src/static.ts',
        },
        output: {
            filename: '[name].js',
            path: path.resolve(__dirname, 'dist'),
            clean: isProduction ? {
                keep: /(favicon\.png|clinkmedev-og-card\.png|CLINK_(dark|light)\.svg|clink-logo\.svg|clink-avatar\.svg|nav\.html|nav\.js)$/,
            } : false,
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
