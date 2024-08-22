class ApiError extends Error {
    public statusCode: number;
    public data: any = null;
    public success: boolean;
    public errors: any[];
    public stack?: string;

    constructor(
        statusCode: number,
        message: string = "Something went wrong",
        errors: any[] = [],
        stack?: string
    ) {
        super(message); // Call the Error constructor with the message
        this.statusCode = statusCode;
        this.errors = errors; // Property name should be `errors` to match the constructor parameter
        this.success = false;

        if (stack) {
            this.stack = stack; // If stack is provided, use it
        } else {
            Error.captureStackTrace(this, this.constructor); // Otherwise, capture the current stack trace
        }

        // Explicitly set the prototype to maintain proper inheritance
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

export { ApiError };
