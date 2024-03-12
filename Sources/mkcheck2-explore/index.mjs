
/**
 * @typedef {{"id": number, "name": string, "exists": boolean}} File
 * @typedef {{"uid": number, "parent": number, "image": number, "output": number[], "input": number[]}} Process
 * @typedef {{"files": File[], "procs": Process[]}} GraphData
 */

class ProcessTree {
    /**
     * @param {GraphData} data
     */
    constructor(data) {
        /** @type {GraphData} */
        this._data = data;
        /** @type {Map<number, Process>} */
        this._processes = new Map();
        /** @type {Map<number, number[]>} */
        this._children = new Map();

        for (const proc of data.procs) {
            this._processes.set(proc.uid, proc);
            if (!this._children.has(proc.parent)) {
                this._children.set(proc.parent, []);
            }
            this._children.get(proc.parent).push(proc.uid);
        }

        /** @type {Map<number, File>} */
        this._files = new Map();
        for (const file of data.files) {
            this._files.set(file.id, file);
        }
    }

    get roots() {
        const rootUids = this._children.get(0) || [];
        return rootUids.map(uid => this._processes.get(uid));
    }

    childrenOf(uid) {
        return this._children.get(uid) || [];
    }

    /**
     * @param {Process} proc 
     */
    infoOf(proc) {
        const imageFile = this._files.get(proc.image);
        const inputFiles = proc.input.map(i => this._files.get(i));
        const outputFiles = proc.output.map(i => this._files.get(i));
        return {imageFile, inputFiles, outputFiles};
    }
}

/**
 * @param {GraphData} data 
 */
export function parseGraph(data) {
    const tree = new ProcessTree(data);
    return tree;
}

/**
 * @param {ProcessTree} tree
 */
export function renderTree(tree, targetElement) {
    const root = document.createElement("ul");
    targetElement.appendChild(root);
    const worklist = [{node: root, procs: tree.roots}];

    const renderProcess = (proc, li) => {
        const info = tree.infoOf(proc);
        const details = document.createElement("details");
        li.appendChild(details);
        const summary = document.createElement("summary");
        summary.textContent = `Process ${proc.uid} (${info.imageFile.name})`;
        details.appendChild(summary);
        const dl = document.createElement("dl");
        details.appendChild(dl);
        const dtImage = document.createElement("dt");
        dtImage.textContent = "Image";
        dl.appendChild(dtImage);
        const ddImage = document.createElement("dd");
        ddImage.textContent = info.imageFile.name;
        dl.appendChild(ddImage);
        const dtInput = document.createElement("dt");
        dtInput.textContent = "Input";
        dl.appendChild(dtInput);
        const ddInput = document.createElement("dd");
        dl.appendChild(ddInput);
        const ulInput = document.createElement("ul");
        ddInput.appendChild(ulInput);
        for (const file of info.inputFiles) {
            const liInput = document.createElement("li");
            liInput.textContent = file.name;
            ulInput.appendChild(liInput);
        }
        const dtOutput = document.createElement("dt");
        dtOutput.textContent = "Output";
        dl.appendChild(dtOutput);
        const ddOutput = document.createElement("dd");
        dl.appendChild(ddOutput);
        const ulOutput = document.createElement("ul");
        ddOutput.appendChild(ulOutput);
        for (const file of info.outputFiles) {
            const liOutput = document.createElement("li");
            liOutput.textContent = file.name;
            ulOutput.appendChild(liOutput);
        }
    };


    while (worklist.length > 0) {
        const {node, procs} = worklist.pop();

        for (const proc of procs) {
            const li = document.createElement("li");
            renderProcess(proc, li);
            node.appendChild(li);

            const children = tree.childrenOf(proc.uid);
            if (children.length > 0) {
                const ul = document.createElement("ul");
                li.appendChild(ul);
                worklist.push({node: ul, procs: children.map(uid => tree._processes.get(uid))});
            }
        }
    }
}
