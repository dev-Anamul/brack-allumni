class APIFeatures {
    constructor(query, queryString) {
        this.query = query;
        this.queryString = queryString;
    }

    filter() {
        // ! shallow copy of query object
        const queryObj = { ...this.queryString };

        // ! define excluded fields
        const excludedFields = ['page', 'sort', 'limit', 'fields', 'keyword'];

        // ! filter out excluded fileds
        excludedFields.map((el) => delete queryObj[el]);

        // ! greater then less then query
        let queryStr = JSON.stringify(queryObj);
        queryStr = queryStr.replace(/\b(gte|gt|lte|lt)\b/g, (match) => `$${match}`);

        // ! we can't await query here.. if await here we can't make other query
        this.query = this.query.find(JSON.parse(queryStr));

        // ! return this
        return this;
    }

    keywordSearch() {
        if (this.queryString.keyword) {
            this.query = this.query.find({
                $or: [
                    { fullName: { $regex: this.queryString.keyword, $options: 'i' } },
                    { email: { $regex: this.queryString.keyword, $options: 'i' } },
                    { contactNumber: { $regex: this.queryString.keyword, $options: 'i' } },
                ],
            });
        }
        return this;
    }

    sort() {
        // ! sorting
        if (this.queryString.sort) {
            const sortBy = this.queryString.sort.split(',').join(' ');
            this.query = this.query.sort(sortBy);
        } else {
            this.query = this.query.sort('-createdAt');
        }
        return this;
    }

    fields() {
        // ! limiting fields
        if (this.queryString.fields) {
            const fields = this.queryString.fields.split(',').join(' ');
            this.query = this.query.select(fields);
        } else {
            this.query = this.query.select('-__v');
        }

        return this;
    }

    pagination() {
        // ! pagination
        const page = this.queryString.page * 1 || 1;
        const limit = this.queryString.limit * 1 || 200;
        const skip = (page - 1) * limit;

        this.query = this.query.skip(skip).limit(limit);

        return this;
    }
}

module.exports = APIFeatures;
