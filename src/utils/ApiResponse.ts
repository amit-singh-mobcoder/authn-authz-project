export class ApiResponse<T> {
    public statusCode: number;
    public data: T;
    public message: string;
    public success: boolean;

    constructor(statusCode:number, data:T, message:string ='Success'){
        this.statusCode = statusCode;
        this.data = data;
        this.message = message;
        this.success = statusCode < 400;
    }

    public static create<T>(statusCode:number, data:T, message:string ='Success'):ApiResponse<T>{
        return new ApiResponse(statusCode, data, message);
    }
}