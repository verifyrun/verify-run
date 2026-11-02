"""Historical logical counters, separately typed; never a physical-cost total."""
from vfy import child_ledger as m, service_adoption_history as history
from vfy import service_adoption as adoption, service_lifecycle as lifecycle

def vector(value,axes):
    m.need(type(value) is dict and set(value)==set(axes))
    m.need(all(type(n) is int and 0<=n<=2**63-1 for n in value.values()),'Invalid historical counter.')
    return dict(value)

def accounting(inputs,policy):
    prep=m.authenticate(m.load.load_json_bytes(inputs['preparation']),policy['owner_trust'])
    done=m.authenticate(m.load.load_json_bytes(inputs['completion']),policy['owner_trust'])
    plan=m.load.load_json_bytes(inputs['plan']);reserved=prep['reserved']
    inventory=vector(prep['input_inventory'],lifecycle.PREP_AXES)
    preparation_limits=vector(reserved['preparation'],lifecycle.PREP_AXES)
    limits=vector(done['resources_reserved'],adoption.RESOURCES)
    measured=vector(done['measured'],adoption.RESOURCES)
    m.need(all(inventory[k]<=preparation_limits[k] for k in inventory))
    m.need(all(measured[k]<=limits[k]==plan['limits'][k]==reserved['adoption'][k] for k in measured),'Historical reservation mismatch.')
    m.need(prep['full_physical_cost']=='UNKNOWN' and type(prep['inventory_scope']) is str)
    return dict(schema='vfy.historical-adoption-accounting/1',
        preparation=dict(input_inventory=inventory,reserved_limits=preparation_limits,
            inventory_scope=prep['inventory_scope'],classification='LOGICAL_PAYLOAD_INVENTORY_AND_ESTIMATE'),
        adoption=dict(measured=measured,reserved_limits=limits,
            classification='INSTRUMENTED_MANAGED_COPY_LOGICAL_COUNTERS'),
        aggregation='NOT_SUMMED',full_physical_cost='UNKNOWN',
        unmeasured=['CPU time','wall time','imports and dependency loading','all filesystem metadata operations','physical storage and IO'],
        reservation_release='NOT_ESTABLISHED',remaining_budget='NOT_ESTABLISHED',**history.FLAGS)

def run(*,request_sha256,stdin,out):
    response=dict(schema='vfy.service-adoption-accounting-response/1',request_sha256=request_sha256,state='REFUSED',result=None,**history.FLAGS)
    code=12
    try:
        raw=stdin.read(history.MAX_BYTES+1)
        m.need(type(raw) is bytes and len(raw)<=history.MAX_BYTES and m.sha(raw)==request_sha256)
        q=m.load.load_json_bytes(raw)
        m.need(set(q)=={'schema','inputs','policy','expected_final_plan_sha256'} and q['schema']=='vfy.verify-service-adoption-accounting-request/1')
        inputs=history.read._inputs(q['inputs'],('plan','preparation','intent','completion'),history.MAX_BYTES)
        checked=history.verify(inputs,q['policy'],q['expected_final_plan_sha256'])
        checked['accounting']=accounting(inputs,q['policy'])
        response.update(result=checked,state='HISTORICAL_ADOPTION_ACCOUNTING_VERIFIED')
        m.need(len(m.raw(response))+1<=65536,'Historical response exceeds bound.')
        code=0
    except Exception:
        response.update(state='REFUSED',result=None)
    out.write((m.raw(response)+b'\n').decode());return code
