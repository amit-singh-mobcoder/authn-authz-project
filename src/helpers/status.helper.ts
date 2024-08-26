
export abstract class StatusHelper {
    public static status200Ok: number = 200;
    public static status201Created: number = 201;
    public static status202Accepted: number = 202;
    public static status204NoContent: number = 204;

    public static error400BadRequest: number = 400; 
    public static error401Unauthorized: number = 401;
    public static error403Forbidden: number = 403;
    public static error404NotFound: number = 404;
    public static error409Conflict: number = 409;

    public static error500InternalServerError: number = 500;
}