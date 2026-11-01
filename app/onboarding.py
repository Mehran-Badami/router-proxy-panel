"""Read-only installation checks. Never infer a ready network from a running panel."""
from sites import Router, preflight

def inspect_router():
    checks=[]
    try:
        router=Router()
        resource=router.request('GET','/system/resource')
        if isinstance(resource,list):resource=resource[0]
        arch=resource.get('architecture-name','')
        version=resource.get('version','')
        compatible=arch in ('arm64','x86','x86_64') and version.startswith('7.')
        checks.append({'name':'سازگاری روتر','ok':compatible,
                       'detail':('RouterOS '+version+' / '+arch) if compatible else 'این بسته به RouterOS 7 و ARM64 یا x86 نیاز دارد'})
        if not compatible:return {'ready':False,'checks':checks}
        preflight(router)
        checks.append({'name':'مسیر تونل و DNS','ok':True,'detail':'پیش‌نیازهای مسیر نصب شده‌اند؛ اتصال واقعی دستگاه‌ها هم باید آزمایش شود'})
        return {'ready':True,'checks':checks}
    except ValueError as error:
        checks.append({'name':'اتصال و آماده‌سازی روتر','ok':False,'detail':str(error)})
    except Exception:
        checks.append({'name':'اتصال روتر','ok':False,'detail':'بررسی روتر کامل نشد؛ راهنمای اتصال را باز کنید'})
    return {'ready':False,'checks':checks}
