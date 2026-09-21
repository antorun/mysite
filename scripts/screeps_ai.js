
// 获取已控制的房间
function getMyRooms() {
    return Object.values(Game.rooms).filter(room => 
        room.controller && 
        room.controller.my
    );
}

// 定义基础身体部件 (300能量)
function getCreepBody(role, energyAvailable) {
    if (energyAvailable >= 300) {
        switch(role) {
            case 'harvester':
                return [WORK, WORK, CARRY, MOVE];  // 300能量
            case 'upgrader':
                return [WORK, CARRY, CARRY, MOVE, MOVE];  // 300能量
            case 'builder':
                return [WORK, CARRY, CARRY, MOVE, MOVE];  // 300能量
        }
    }
    return [WORK, CARRY, MOVE];  // 200能量
}

// 生成creep
function spawnCreep(spawn, role, sourceId) {
    // 获取房间内所有源
    const sources = spawn.room.find(FIND_SOURCES);
    const secondSource = sources[1];  // 只有一个位置的源
    
    // 计算每个源当前的采集者数量
    const creepsAtSource1 = _.filter(Game.creeps, creep => 
        creep.memory.sourceId === sources[0].id
    ).length;
    
    const creepsAtSource2 = _.filter(Game.creeps, creep => 
        creep.memory.sourceId === secondSource.id
    ).length;

    // 决定使用哪个源
    let targetSourceId;
    if(role === 'harvester') {
        // 如果第二个源还没有采集者，优先分配
        if(creepsAtSource2 === 0) {
            targetSourceId = secondSource.id;
        } else if(creepsAtSource1 < 3) {
            // 否则，如果第一个源还没满，使用第一个源
            targetSourceId = sources[0].id;
        } else {
            // 如果都满了，返回null
            return ERR_BUSY;
        }
    } else {
        // 非采集者优先使用第一个源（如果还有空位）
        targetSourceId = creepsAtSource1 < 3 ? sources[0].id : secondSource.id;
    }

    // 生成 creep
    const newName = role + Game.time;
    const result = spawn.spawnCreep(
        getCreepBody(role, spawn.room.energyAvailable),
        newName,
        {
            memory: {
                role: role,
                sourceId: targetSourceId,
                room: spawn.room.name
            }
        }
    );

    if(result === OK) {
        console.log('正在生成新的 ' + role + ': ' + newName);
    }
    return result;
}

// 主循环
function main() {
    const myRooms = getMyRooms();
    
    for(let room of myRooms) {
        // 检查是否只有一个spawn
        const spawns = room.find(FIND_MY_SPAWNS);
        if (spawns.length !== 1) continue;
        
        const spawn = spawns[0];
        const sources = room.find(FIND_SOURCES);
        
        // 计算当前creep数量
        const harvesters = _.filter(Game.creeps, creep => 
            creep.memory.role === 'harvester' &&
            creep.room.name === room.name
        );
        
        const upgraders = _.filter(Game.creeps, creep => 
            creep.memory.role === 'upgrader' &&
            creep.room.name === room.name
        );
        
        const builders = _.filter(Game.creeps, creep => 
            creep.memory.role === 'builder' &&
            creep.room.name === room.name
        );
        
        // 修改生成顺序和源分配
        if (harvesters.length < 2) {
            const sourceIndex = harvesters.length;
            if (sourceIndex < sources.length) {
                spawnCreep(spawn, 'harvester', sources[sourceIndex].id);
            }
        } else if (upgraders.length < 1) {
            // 升级者使用第一个能量源
            spawnCreep(spawn, 'upgrader', sources[0].id);
        } else if (builders.length < 1) {
            // 建造者使用第二个能量源（如果有的话）
            const builderSourceId = sources.length > 1 ? sources[1].id : sources[0].id;
            spawnCreep(spawn, 'builder', builderSourceId);
        }
        
        // 运行所有creep的工作逻辑
        for(let name in Game.creeps) {
            const creep = Game.creeps[name];
            if(creep.memory.role === 'harvester') {
                runHarvester(creep);
            } else if(creep.memory.role === 'upgrader') {
                runUpgrader(creep);
            } else if(creep.memory.role === 'builder') {
                runBuilder(creep);
            }
        }
    }
    
    // 清理死亡creep的内存
    for(let name in Memory.creeps) {
        if(!Game.creeps[name]) {
            delete Memory.creeps[name];
        }
    }
}

// 检查源是否可用，并考虑位置限制
function isSourceAvailable(source, creep) {
    const sources = source.room.find(FIND_SOURCES);
    const isSecondSource = source.id === sources[1].id;  // 判断是否是第二个源（只有1个位置的）
    
    // 如果是第二个源，检查是否已经有creep在采集
    if(isSecondSource) {
        const creepsHere = source.pos.findInRange(FIND_CREEPS, 1);
        return creepsHere.length === 0;  // 只有当没有creep时才返回true
    }
    
    // 第一个源（3个位置的），检查当前creep数量
    const creepsHere = source.pos.findInRange(FIND_CREEPS, 1);
    return creepsHere.length < 3;
}

// 寻找可用的能量源
function findAvailableSource(creep) {
    const sources = creep.room.find(FIND_SOURCES);
    
    // 先尝试使用当前分配的源
    const currentSource = Game.getObjectById(creep.memory.sourceId);
    if(currentSource && isSourceAvailable(currentSource, creep)) {
        return currentSource;
    }
    
    // 如果当前源不可用，寻找新的源
    // 优先使用第一个源（3个位置的）
    if(isSourceAvailable(sources[0], creep)) {
        creep.memory.sourceId = sources[0].id;
        return sources[0];
    }
    
    // 最后才尝试使用第二个源（1个位置的）
    if(isSourceAvailable(sources[1], creep)) {
        creep.memory.sourceId = sources[1].id;
        return sources[1];
    }
    
    return null;
}

// 获取源周围可用的采集位置数量
function getAccessiblePositions(source) {
    let count = 0;
    const terrain = source.room.getTerrain();
    
    for(let x = source.pos.x - 1; x <= source.pos.x + 1; x++) {
        for(let y = source.pos.y - 1; y <= source.pos.y + 1; y++) {
            if(x === source.pos.x && y === source.pos.y) continue;
            if(terrain.get(x, y) !== TERRAIN_MASK_WALL) {
                count++;
            }
        }
    }
    return count;
}

// 采集逻辑
function runHarvester(creep) {
    if(creep.memory.harvesting) {
        if(creep.store.getFreeCapacity() > 0) {
            const source = Game.getObjectById(creep.memory.harvestTarget);
            if(source) {
                if(creep.harvest(source) == ERR_NOT_IN_RANGE) {
                    creep.moveTo(source);
                }
            }
        } else {
            creep.memory.harvesting = false;
            // 查找最近的能量容器
            const container = creep.pos.findClosestByPath(FIND_STRUCTURES, {
                filter: (structure) => {
                    return structure.structureType === STRUCTURE_CONTAINER &&
                           structure.store.getFreeCapacity(RESOURCE_ENERGY) > 0;
                }
            });
            // 如果找到容器，将能量转移到容器中
            if(container) {
                // 检查容器的生命值
                if(container.hits < container.hitsMax * 0.8) {
                    // 如果容器生命值低于80%，先修理
                    if(creep.repair(container) === ERR_NOT_IN_RANGE) {
                        creep.moveTo(container);
                    }
                } else {
                    // 否则，将能量转移到容器中
                    if(creep.transfer(container, RESOURCE_ENERGY) === ERR_NOT_IN_RANGE) {
                        creep.moveTo(container);
                    }
                }
            } else {
                // 如果容器已满或不存在，寻找建筑工地
                const constructionSite = creep.pos.findClosestByPath(FIND_CONSTRUCTION_SITES);
                if(constructionSite) {
                    if(creep.build(constructionSite) === ERR_NOT_IN_RANGE) {
                        creep.moveTo(constructionSite);
                    }
                }
            }
        }
    } else {
        const sources = creep.room.find(FIND_SOURCES);
        const availableSources = sources.filter(source => {
            const harvesters = _.filter(Game.creeps, (c) => 
                c.memory.harvestTarget == source.id && 
                c.memory.harvesting
            );
            return harvesters.length < getAccessiblePositions(source);
        });
        
        if(availableSources.length > 0) {
            const closestSource = creep.pos.findClosestByPath(availableSources);
            if(closestSource) {
                creep.memory.harvestTarget = closestSource.id;
                creep.memory.harvesting = true;
                if(creep.harvest(closestSource) == ERR_NOT_IN_RANGE) {
                    creep.moveTo(closestSource);
                }
            }
        }
    }
}

// 修改建造者逻辑
function runBuilder(creep) {
    if(creep.memory.building && creep.store[RESOURCE_ENERGY] == 0) {
        creep.memory.building = false;
        creep.say('🔄 harvest');
    }
    if(!creep.memory.building && creep.store.getFreeCapacity() == 0) {
        creep.memory.building = true;
        creep.say('🚧 build');
    }

    if(creep.memory.building) {
        const targets = creep.room.find(FIND_CONSTRUCTION_SITES);
        if(targets.length) {
            if(creep.build(targets[0]) == ERR_NOT_IN_RANGE) {
                creep.moveTo(targets[0], {visualizePathStyle: {stroke: '#ffffff'}});
            }
        }
    } else {
        // 查找掉落的资源
        const droppedResources = creep.room.find(FIND_DROPPED_RESOURCES);
        if(droppedResources.length) {
            if(creep.pickup(droppedResources[0]) == ERR_NOT_IN_RANGE) {
                creep.moveTo(droppedResources[0], {visualizePathStyle: {stroke: '#ffaa00'}});
            }
        } else {
            const sources = creep.room.find(FIND_SOURCES);
            if(sources.length) {
                if(creep.harvest(sources[0]) == ERR_NOT_IN_RANGE) {
                    creep.moveTo(sources[0], {visualizePathStyle: {stroke: '#ffaa00'}});
                }
            }
        }
    }
}

// 定义 runUpgrader 函数
function runUpgrader(creep) {
    if(creep.memory.upgrading && creep.store[RESOURCE_ENERGY] == 0) {
        creep.memory.upgrading = false;
    }
    if(!creep.memory.upgrading && creep.store.getFreeCapacity() == 0) {
        creep.memory.upgrading = true;
    }

    if(creep.memory.upgrading) {
        if(creep.upgradeController(creep.room.controller) == ERR_NOT_IN_RANGE) {
            creep.moveTo(creep.room.controller);
        }
    } else {
        const source = creep.pos.findClosestByPath(FIND_SOURCES_ACTIVE);
        if(source && creep.harvest(source) == ERR_NOT_IN_RANGE) {
            creep.moveTo(source);
        }
    }
}

module.exports.loop = main;