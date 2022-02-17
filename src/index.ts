import { NextFunction, Request, Response } from "express";

/**Interface */

interface PermissionObject {
    description?: string
    trigger: (req: Request) => boolean,
    condition?: (req: Request, resource?: any) => boolean,
    writeFilter?: {
        required?: string[],
        optional?: string[],
    }
    readFilter?: {
        include?: string[],
        exclude?: string[],
    }
}

interface ExtraArguments {
    fetchResource?: (req: Express.Request) => Promise<any>
    customError?: {
        accessDenied?: (res: Response) => Response
        unauthorised?: (res: Response) => Response
        badRequest?: (res: Response) => Response
    }
    showLogs?: boolean
}

//** Error Class */
class AuthMax extends Error {
    constructor(message: string) {
        super(message)

        // assign the error class name in your custom error (as a shortcut)
        this.name = this.constructor.name

        // capturing the stack trace keeps the reference to your error class
        Error.captureStackTrace(this, this.constructor);
    }
}

//**Main fucntion */
export const authMax = (permissionList: PermissionObject[] = [], extraArguments: ExtraArguments) => {
    return async (req: any, res: Response, next: NextFunction) => {
        try {
            //defaults
            const { customError } = extraArguments;
            let unauthorizedErr = (res: Response): Response => res.status(403).json({ msg: 'unauthorised' });
            let accessDenyErr = (res: Response): Response => res.status(401).json({ msg: 'access denided' });
            let badRequestErr = (res: Response): Response => res.status(400).json({ msg: 'bad request' });
            //

            if (customError) {
                const { unauthorised, badRequest, accessDenied } = customError;

                if (accessDenied) {
                    if (!(typeof accessDenied === 'function')) throw new AuthMax('accessDenied error must be a function');
                    if (!(accessDenied.length === 1)) throw new AuthMax('accessDenied error requires one argument')
                    accessDenyErr = accessDenied;
                }

                if (unauthorised) {
                    if (!(typeof unauthorised === 'function')) throw new AuthMax('unauthorized error must be a function');
                    if (!(unauthorised.length === 1)) throw new AuthMax('unauthorized error requires one argument')
                    unauthorizedErr = unauthorised;
                }

                if (badRequest) {
                    if (!(typeof badRequest === 'function')) throw new AuthMax('badRequest error must be a function');
                    if (!(badRequest.length === 1)) throw new AuthMax('badRequest error requires one argument')
                    badRequestErr = badRequest;
                }
            }

            //**Log code */
            if (extraArguments.showLogs) {
                const permissionListLog: any = [];
                if (!Array.isArray(permissionList)) throw new AuthMax('first argument must be an array');
                if (!permissionList.every(e => e.trigger)) throw new AuthMax('trigger is mising in one of the permissionObject');
                if (extraArguments.fetchResource) {
                    req.resource = await runFetchResource(extraArguments, req, res);
                }
                permissionList.forEach(permission => {
                    let permissionCopy: any = permission;
                    permissionCopy.triggerValue = permission.trigger(req);
                    if (permission.condition) {
                        permissionCopy.conditionValue = permission.condition(req, req.resource);
                    }
                    permissionListLog.push(permissionCopy);

                });
                const permissionPicked = permissionList.find(p => p?.trigger(req));
                const authMax: any = {
                    permissionListLog,
                    permissionPicked
                }
                if (extraArguments.fetchResource) authMax.fetchResourceValue = req.resource;
                console.log(authMax);
            }
            //**log end here */


            if (!Array.isArray(permissionList)) throw new AuthMax('first argument must be an array');
            if (!permissionList.every(e => e.trigger)) throw new AuthMax('trigger is mising in one of the permissionObject');
            const permission = permissionList.find(p => p?.trigger(req) ? true : false);  // check all condition have trigger.
            if (!permission) {
                return accessDenyErr(res)
            };

            if (permission.condition) {
                    if (!(typeof permission.condition === 'function')) throw new AuthMax('condition property is not a function');
                    if (permission.condition.length == 0 || permission.condition.length > 2) throw new AuthMax('condition property only accepty maximum two argumnet in the function');
                    if (permission.condition.length === 1) {
                        if (!permission.condition(req)) return unauthorizedErr(res);
                    } else if (permission.condition.length === 2) {
                        // check the fetch resource function availability
                        await runFetchResource(extraArguments, req, next);
                        if (!permission.condition(req, req.resource)) return unauthorizedErr(res);
                    }
                }

            if (permission.readFilter) {
                if (!(typeof permission.readFilter === 'object')) throw new AuthMax('readFilter should be an object');
                if (!(permission.readFilter.include || permission.readFilter.exclude)) throw new AuthMax('readFilter should contain either include or exclude property');
                if (!((permission.readFilter.include && Array.isArray(permission.readFilter.include) || (permission.readFilter.exclude && Array.isArray(permission.readFilter.exclude))))) throw new AuthMax('readFilter should contain either include or exclude and must be an array');
                if (!(req.resource && typeof req.resource == 'object')) await runFetchResource(extraArguments, req, next);
                if (permission.readFilter.include) req.resource.filter = () => pick(req.resource, permission.readFilter?.include);
                else req.resource.filter = () => omit(req.resource, permission.readFilter?.exclude);
            }

            if (permission.writeFilter) {
                if (!(typeof permission.writeFilter === 'object')) throw new AuthMax('writeFilter should be an object');
                if (!(permission.writeFilter.required || permission.writeFilter.optional)) throw new AuthMax('writeFilter should contain required or optional or both property');
                if (!((permission.writeFilter.required && Array.isArray(permission.writeFilter.required) || (permission.writeFilter.optional && Array.isArray(permission.writeFilter.optional))))) throw new AuthMax('writeFilter should contain either required or optional or both and must be an array');
                if (!(req.body && typeof req.body == 'object')) throw new AuthMax('writeFilter only applies to create and update operation,request body is either null or not an object');
                const { required = [], optional = [] } = permission.writeFilter;
                const bodyFields = Object.keys(req.body);
                if (!(bodyFields.length >= required.length && bodyFields.length < required.length + optional.length + 1)) return badRequestErr(res);
                let reqInBodyCount = 0;
                let optInBodyCount = 0;
                let unknownBodyCount = 0;
                bodyFields.forEach(f => {
                    if (required.includes(f)) reqInBodyCount++;
                    else if (optional.includes(f)) optInBodyCount++;
                    else unknownBodyCount++;
                });

                if (!(reqInBodyCount === required.length && optInBodyCount <= optional.length && unknownBodyCount === 0)) return badRequestErr(res);
            }

            next();
        } catch (err) {
            next(err);
        }
    }
}

async function runFetchResource(extraArguments: ExtraArguments, req: any, next: any) {
    if (!(extraArguments.fetchResource))
        throw new AuthMax('fetchResource not provided. Using resource in condition requires fetchResource function in extraArguments parameter.');
    if (!(typeof extraArguments.fetchResource === 'function'))
        throw new AuthMax('fetchResource parameter is not a fuction');
    if (!(extraArguments.fetchResource.length === 1))
        throw new AuthMax('fetchResource only requires one parameter');
    let resource;
    try {
        resource = await extraArguments.fetchResource(req);
    } catch (err) {
        next(err);
    }
    req.resource = resource;
    return req.resource;
}

const pick = (obj: any, keys: any) =>
    Object.keys(obj)
        .filter(i => keys.includes(i))
        .reduce((acc: any, key: any) => {
            acc[key] = obj[key];
            return acc;
        }, {})


const omit = (obj: any, keys: any) =>
    Object.fromEntries(
        Object.entries(obj)
            .filter(([k]) => !keys.includes(k))
    )