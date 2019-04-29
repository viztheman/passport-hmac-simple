const expect = require('chai').expect;

const index = require('..');

describe('index', () => {
    it('should export Strategy directly', () => {
        expect(index).to.be.a('function');
        expect(index).to.equal(index.Strategy);
    });

    it('should export Strategy class', () => {
        expect(index.Strategy).to.be.a('function');
    });
});
