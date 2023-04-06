#include "./libmem.h"
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/mman.h>
#include <stdlib.h>

#define FOR_EACH_BLOCK(block) for(block_t* block = block_first(); block != NULL; block = block_next(block))

// IMPORTANT(Alexis Brodeur): Dans ce fichier, et tout code utilisé par ce fichier,
// vous ne pouvez pas utiliser `malloc`, `free`, etc.

static struct {
    void* ptr;
    size_t len;
    mem_strategy_t strategy;
    void* last_allocated_block;
} state;

// IMPORTANT(Alexis Brodeur): Avant de commencer à implémenter le code de ce
// laboratoire, discuter en équipe afin d'être sûr de tous avoir compris la
// structure de données ce-dessous.

typedef struct block {
    struct block* previous;
    size_t size;
    bool free;
    // NOTE(Alexis Brodeur): Vous pouvez ajouter des champs à cette structure de
    // données, mais vous aller perdre des points pour la qualitée.
} block_t;

/**
 * @brief Retourne le premier bloc dans la liste de blocs.
 *
 * @return Le premier bloc
 */
static inline block_t* block_first()
{
    // IMPORTANT(Alexis Brodeur): Voici un indice !
    return state.ptr;
}

/**
 * @brief Retourne le prochain bloc dans la liste de blocks.
 * @note Retourne @e NULL s'il n'y a pas de prochain bloc.
 *
 * @param block Un bloc
 * @return Le prochain bloc
 */
static block_t* block_next(block_t* block)
{
    char* next_address = (char*) (block + 1) + block->size;

    return next_address >= (char*) state.ptr + state.len ? NULL : (block_t*) next_address;
}

/**
 * @brief
 *
 *
 * mémoire.
 *
 * @param block Le noeud libre à utiliser
 * @param size La taille de l'allocation
 */
static void block_acquire(block_t* block, size_t size)
{
    assert(block != NULL);
    assert(block->size >= size);
    assert(block->free);

    // TODO(Alexis Brodeur): À implémenter.
    //
    // IMPORTANT(Alexis Brodeur):
    // Que faire si `block->size > size` ?  Utiliser les 1000 octets d'un bloc
    // libre pour une allocation de 10 octets ne fait pas de sens.
    size_t size_remaining = block->size - size;
    if (size_remaining > sizeof(block_t)) {
        // Créer un nouveau bloc
        block->size = size;
        block_t* new_block = block_next(block);
        new_block->size = size_remaining - sizeof(block_t);
        new_block->previous = block;
        new_block->free = true;

        // changer l'adresse, le bloc précédent et la taille de block
        //&block += size;

        // Changer le bloc précédent du bloc suivant block
        block_t* next_block = block_next(new_block);
        if (next_block != NULL) {
            next_block->previous = new_block;
        }
    }

    block->free = false;
}

/**
 * @brief Relâche la mémoire utilisé par une allocation, et fusionne le bloc
 * avec son précédant et suivant lorsque nécessaire.
 *
 * @param block Un bloc à relâcher
 */
static void block_release(block_t* block)
{
    assert(block != NULL);
    assert(!block->free);

    block_t* next_block = block_next(block);
    block_t* previous_block = block->previous;

    block->free = true;

    // si le bloc précédent est libre
    if (previous_block != NULL && previous_block->free == true){
        //joindre blocs ensemble
        previous_block->size += block->size + sizeof(block_t);
        block = previous_block;
    }

    // si le bloc suivant est libre
    if (next_block != NULL) {
        if (next_block->free == true) {
            //joindre blocs ensemble
            block->size += next_block->size + sizeof(block_t);
            if (block_next(block) != NULL) {
                block_next(block)->previous = block;
            }
        }
        else {
            next_block->previous = block;
        }
    }
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void mem_init(size_t size, mem_strategy_t strategy)
{
    assert(size > 0);
    assert(strategy >= 0);
    assert(strategy < NUM_MEM_STRATEGIES);

    // TODO(Alexis Brodeur): Initialiser l'allocation de mémoire.

    // IMPORTANT(Alexis Brodeur): Combien avec-vous de blocs initialement ?

    // IMPORTANT(Alexis Brodeur): Comment obtenir de la mémoire sans utiliser
    // `malloc` ?
    state.strategy = strategy;
    state.len = size;
    state.last_allocated_block = NULL;

    state.ptr = (void*) mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    //gestion d'erreur
    if(state.ptr == MAP_FAILED){
        exit(EXIT_FAILURE);
    }

    block_t* block = block_first();
    block->free = true;
    block->previous = NULL;
    block->size = size - sizeof(block_t);
}

void mem_deinit(void)
{
    // TODO(Alexis Brodeur): Libérez la mémoire utilisée par votre gestionnaire.
    // utiliser mummap
    if (munmap(state.ptr, state.len) == -1) {
        exit(EXIT_FAILURE);
    }
}

void* mem_alloc(size_t size)
{
    assert(size > 0);

    // TODO(Alexis Brodeur): Alloue un bloc de `size` octets.
    //
    // Ce bloc et ses métadonnées doivent être réservées dans la mémoire pointée
    // par `state.ptr`.

    // NOTE(Alexis Brodeur): Utiliser la structure `block_t` ci-dessus et les
    // ses fonctions associées.
    //
    // Venez me poser des questions si cela n'est pas clair !

    block_t* requested_block = NULL;
    size_t requested_block_size;

    switch(state.strategy) {
        case MEM_FIRST_FIT:

            FOR_EACH_BLOCK(block) {
                if (block->free == true && block->size >= size) {
                    requested_block = block;
                    break;
                }
            }
            break;

        case MEM_BEST_FIT:

            requested_block_size = state.len;

            FOR_EACH_BLOCK(block) {
                if ((block->free == true) && (block->size >= size) && (block->size < requested_block_size)) {
                    requested_block = block;
                    requested_block_size = block->size;
                }
            }
            break;

        case MEM_WORST_FIT:

            requested_block_size = 0;

            FOR_EACH_BLOCK(block) {
                if ((block->free == true) && (block->size > requested_block_size) && (block->size >= size)) {
                    requested_block = block;
                    requested_block_size = block->size;
                }
            }
            break;

        case MEM_NEXT_FIT:
        if (state.last_allocated_block == NULL) {
            requested_block = (block_t*) block_first();
            break;
        }

        block_t* last_allocated_block = state.last_allocated_block;
        block_t* starting_block = block_next(mem_get_block_start(last_allocated_block));
        block_t* current_block = starting_block;
        if (current_block == NULL && last_allocated_block == block_first()) {
            if (last_allocated_block->free == true && last_allocated_block->size > size){
                requested_block = last_allocated_block;
            }
            break;
        }
        do {
            if (current_block == NULL) {
                current_block = state.ptr;
            }
            if (current_block->free == true && current_block->size >= size) {
                requested_block = current_block;
                break;
            }
            current_block = block_next(current_block);
        } while (current_block != starting_block);

        break;
    }

    if(requested_block == NULL) {
        return NULL;
    }

    state.last_allocated_block = requested_block;

    block_acquire(requested_block, size);

    return requested_block + 1;
}

void mem_free(void* ptr)
{
    assert(ptr != NULL);

    // TODO(Alexis Brodeur): Libère le bloc de mémoire pointé par `ptr`.
    //
    // Assumez que `ptr` est TOUJOURS un pointeur retourné par `mem_alloc`.
    block_release((block_t*) ptr -1);
}

size_t mem_get_free_block_count()
{
    block_t* block = state.ptr;
    int block_count = block->free == true ? 1 : 0;

    while(block_next(block) != NULL) {

        block = block_next(block);

        if (block->free == true) {
            block_count += 1;
        }
    }

    return block_count;
}

size_t mem_get_allocated_block_count()
{
    block_t* block = state.ptr;
    int block_count = block->free == false ? 1 : 0;

    while(block_next(block) != NULL) {

        block = block_next(block);

        if (block->free == false) {
            block_count += 1;
        }
    }

    return block_count;
}

size_t mem_get_free_bytes()
{
    // TODO(Alexis Brodeur): Indiquez combien d'octets sont disponibles pour
    // des allocations de mémoire.

    block_t* block = state.ptr;
    size_t byte_count = block->free == true ? block->size : 0;

    while(block_next(block) != NULL) {

        block = block_next(block);

        if (block->free == true) {
            byte_count += block->size;
        }
    }

    return byte_count;
}

size_t mem_get_biggest_free_block_size()
{
    // TODO(Alexis Brodeur): Indiquez la taille en octets du plus gros plus de
    // mémoire libre.

    block_t* block = state.ptr;
    size_t biggest_free_space_size = block->free == true ? block->size : 0;

    while(block_next(block) != NULL) {

        block = block_next(block);

        if (block->free == true && block->size > biggest_free_space_size) {
            biggest_free_space_size = block->size;
        }
    }

    return biggest_free_space_size;
}

size_t mem_count_small_free_blocks(size_t max_bytes)
{
    assert(max_bytes > 0);

    // TODO(Alexis Brodeur): Indiquez combien de blocs de mémoire plus petit que
    // `max_bytes` sont disponible.

    assert(max_bytes > 0);

    block_t* block = state.ptr;
    int block_count = (block->free == true) && (block->size < max_bytes) ? 1 : 0;

    while(block_next(block) != NULL) {

        block = block_next(block);

        if ((block->free == true) && (block->size < max_bytes)) {
            block_count += 1;
        }
    }

    return block_count;
}

bool mem_is_allocated(void* ptr)
{
    assert(ptr != NULL);

    // TODO(Alexis Brodeur): Indiquez si l'octet pointé par `ptr` est alloué.

    // NOTE(Alexis Brodeur): Ce pointeur peut pointer vers n'importe quelle
    // adresse mémoire.

    block_t* block = state.ptr;

    FOR_EACH_BLOCK(block) {
        void* block_address = (void*) block;
        void* next_address = (void*) ((char*) (block + 1) + block->size);
        if (block_address <= ptr && next_address > ptr) {
            return !block->previous->free;
            break;
        }
    }

    return false;
}

void* mem_get_block_start (void* ptr)
{
    block_t* block = ptr;
    block_t* previous_block = block->previous;

    if (previous_block == NULL) {
        previous_block = block_first();
    }
    else if (block_next(previous_block) != block) {
        block = previous_block;
    }

    return block;
}

void mem_print_state(void)
{
    // TODO(Alexis Brodeur): Imprimez l'état de votre structure de données.
    //
    //   - Affichez les blocs en ordre.
    //   - Un bloc alloué commence par un 'A', tandis qu'un bloc libre commence
    //     par 'F'.
    //   - Après la lettre, imprimez la taille du bloc.
    //   - Séparez les blocs par un espace.
    //   - Cela ne dérange pas s'il y a un espace supplémentaire à la fin de la
    //     ligne.
    //
    // Ex.:
    //
    // ```
    // A100 F24 A20 A58 F20 A27 F600
    // ```

    block_t* block = state.ptr;

    if (block->free == true) {
        printf("F");
    }
    else {
        printf("A");
    }

    printf("%lu ", block->size);

    while(block_next(block) != NULL) {

        block = block_next(block);

        if (block->free == true) {
        printf("F");
        }
        else {
            printf("A");
        }

        printf("%lu ", block->size);
    }
}
